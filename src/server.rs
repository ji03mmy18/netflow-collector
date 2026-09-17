use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use arc_swap::ArcSwap;
use chrono::Utc;
use netflow_parser::NetflowParser;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{error, warn};

use crate::aggregator::{bucket_of, Aggregator};
use crate::db::{FlowRow, FlushBatch, IntraCidr};
use crate::filter::FilterConfig;
use crate::live::LiveRecord;
use crate::stats::{HealthAccumulator, SequenceTracker, Stats};
use crate::{parser, printer};

/// Everything the database path needs.  Absent when `--db-store` is off, in
/// which case the collector is a pure display tool and never touches the
/// monitored list.
pub struct DbPipeline {
    pub raw_tx: mpsc::Sender<FlowRow>,
    pub flush_tx: mpsc::Sender<FlushBatch>,
    pub intra: IntraCidr,
    pub sampling_interval: i32,
    pub clock_skew_threshold_ms: i64,
    pub flush_seconds: u64,
}

pub struct RunOptions {
    pub direct_print: bool,
    pub color: bool,
}

/// Main UDP receive loop.  Runs forever; never returns under normal operation.
pub async fn run(
    socket: UdpSocket,
    filter_config: Arc<ArcSwap<FilterConfig>>,
    stats: Arc<Stats>,
    opts: RunOptions,
    db: Option<DbPipeline>,
    live_tx: Option<mpsc::Sender<LiveRecord>>,
) {
    let mut buf = vec![0u8; 65535];
    let mut netflow_parser = NetflowParser::default();

    let mut aggregator = Aggregator::new();
    let mut sequences = SequenceTracker::default();
    let mut health = HealthAccumulator::new(&stats);

    // When there is no database pipeline nothing is ever flushed, but the timer
    // still has to exist for the select! below; make it slow and harmless.
    let flush_secs = db.as_ref().map(|d| d.flush_seconds).unwrap_or(3600);
    let mut flush_ticker = interval(Duration::from_secs(flush_secs.max(1)));
    flush_ticker.tick().await; // consume the immediate first tick

    if opts.direct_print {
        printer::print_header();
    }

    loop {
        tokio::select! {
            // Flushing the aggregator is the only thing allowed to interrupt
            // receiving, and it only sends an already-built batch down a
            // channel — no database round trip happens on this task.
            _ = flush_ticker.tick() => {
                if let Some(ref db) = db {
                    flush(&mut aggregator, &mut health, &stats, db);
                }
            }

            result = socket.recv(&mut buf) => {
                let len = match result {
                    Ok(n) => n,
                    Err(e) => {
                        error!("recv error: {}", e);
                        continue;
                    }
                };

                // One receive time per UDP packet, used only to cross-check the
                // timestamps the exporter put in the packet.
                let received_at = Utc::now();
                stats.received.fetch_add(1, Ordering::Relaxed);

                let parsed = parser::parse(&mut netflow_parser, &buf[..len]);

                health.packet(parsed.has_error);
                if parsed.has_error {
                    stats.failed.fetch_add(1, Ordering::Relaxed);
                }

                for (sequence, count) in &parsed.sequences {
                    let lost = sequences.observe(*sequence, *count);
                    if lost > 0 {
                        stats.seq_gap.fetch_add(lost, Ordering::Relaxed);
                        health.lost(lost);
                    }
                }

                if parsed.flows.is_empty() {
                    continue;
                }
                stats.parsed.fetch_add(parsed.flows.len() as u64, Ordering::Relaxed);

                let fc = filter_config.load();
                let mut matched_here = 0usize;

                for flow in &parsed.flows {
                    let src_ip = u32::from(flow.src_addr);
                    let dst_ip = u32::from(flow.dst_addr);

                    // One filter decides everything: whether the flow is
                    // printed, whether it is stored, and which side of it the
                    // statistics are written from.  `src_matched` means a
                    // filtered address sent this flow, `dst_matched` that one
                    // received it — exactly the distinction tx/rx needs.
                    let matched = fc.check(src_ip, dst_ip);

                    if matched.is_match() {
                        if opts.direct_print {
                            let ctx = printer::PrintContext {
                                color: opts.color,
                                src_matched: matched.src_matched,
                                dst_matched: matched.dst_matched,
                                highlighted_ports: &fc.highlighted_ports,
                            };
                            printer::print_flow(
                                flow.src_addr,
                                flow.src_port,
                                flow.dst_addr,
                                flow.dst_port,
                                flow.d_pkts,
                                flow.d_octets,
                                &ctx,
                            );
                        }

                        if let Some(ref tx) = live_tx {
                            let rec = LiveRecord {
                                src_addr: flow.src_addr,
                                src_port: flow.src_port,
                                dst_addr: flow.dst_addr,
                                dst_port: flow.dst_port,
                                d_pkts: flow.d_pkts,
                                d_octets: flow.d_octets,
                                src_matched: matched.src_matched,
                                dst_matched: matched.dst_matched,
                            };
                            // Best-effort: drop on full channel (display is non-critical).
                            let _ = tx.try_send(rec);
                        }
                    }

                    // ── storage path ────────────────────────────────────────
                    let Some(ref db) = db else { continue };

                    // A filtered host talking to an unfiltered address inside
                    // the CIDR still counts towards that host's intra_tx, which
                    // is why `direction = "any"` (the default) is what you want
                    // for accounting: it matches on either end.  A rule that
                    // only matched when *both* ends were listed would erase that
                    // traffic while leaving every ext_* figure looking normal.
                    if !matched.is_match() {
                        continue;
                    }

                    matched_here += 1;
                    stats.matched.fetch_add(1, Ordering::Relaxed);

                    // The exporter's clock is trusted only as far as it agrees
                    // with ours; past the threshold we fall back to receive time
                    // so a broken NTP degrades the data instead of scattering it
                    // into buckets hours away.
                    let skew_ms = (received_at - flow.ts).num_milliseconds();
                    let rejected = skew_ms.abs() > db.clock_skew_threshold_ms;
                    health.clock_skew(skew_ms, rejected);
                    let ts = if rejected { received_at } else { flow.ts };

                    let row = FlowRow {
                        ts,
                        src_addr: IpAddr::V4(flow.src_addr),
                        dst_addr: IpAddr::V4(flow.dst_addr),
                        src_port: flow.src_port as i32,
                        dst_port: flow.dst_port as i32,
                        protocol: flow.protocol_number as i16,
                        packets: flow.d_pkts as i64,
                        bytes: flow.d_octets as i64,
                        tcp_flags: flow.tcp_flags as i16,
                        input: flow.input as i32,
                        output: flow.output as i32,
                        tos: flow.tos as i16,
                        sampling_interval: db.sampling_interval,
                    };
                    if db.raw_tx.try_send(row).is_err() {
                        stats.db_failed.fetch_add(1, Ordering::Relaxed);
                    }

                    // ── classification ──────────────────────────────────────
                    // "Sent" and "received" are only meaningful relative to a
                    // particular monitored host, so one flow produces one row
                    // per monitored end — two when both ends are on the list.
                    let bucket = bucket_of(ts);
                    let bytes = flow.d_octets as i64 * db.sampling_interval as i64;

                    if matched.src_matched {
                        aggregator.add_tx(bucket, src_ip, db.intra.contains(dst_ip), bytes);
                    }
                    if matched.dst_matched {
                        aggregator.add_rx(bucket, dst_ip, db.intra.contains(src_ip), bytes);
                    }
                }

                health.flows(parsed.flows.len(), matched_here);
            }
        }
    }
}

/// Hand one window's deltas to the statistics writer.
///
/// Uses `try_send` so that a stalled database can never back-pressure the
/// receive loop into dropping UDP packets.  The channel holds a minute's work
/// per slot, so filling it means the writer has been stuck for the best part of
/// an hour — at which point the deltas are still recoverable from `flow_raw`.
fn flush(
    aggregator: &mut Aggregator,
    health: &mut HealthAccumulator,
    stats: &Arc<Stats>,
    db: &DbPipeline,
) {
    let (buckets, days) = aggregator.drain();
    let row = health.take(stats, Utc::now());

    // A health row goes out every window unconditionally, even an entirely idle
    // one.  That is the point of the table: a row of zeroes means "collector up,
    // nothing arrived", while a *missing* row means the collector itself was
    // down.  Skipping empty windows would collapse those two very different
    // situations into the same gap — and would also discard the write counters,
    // which `take` has already consumed by this point.
    let batch = FlushBatch {
        buckets,
        days,
        health: row,
    };

    if let Err(e) = db.flush_tx.try_send(batch) {
        let dropped = match &e {
            mpsc::error::TrySendError::Full(b) => b.buckets.len(),
            mpsc::error::TrySendError::Closed(b) => b.buckets.len(),
        };
        stats.stat_failed.fetch_add(dropped as u64, Ordering::Relaxed);
        warn!(
            rows = dropped,
            "statistics writer is not keeping up; deltas dropped (recoverable with --recompute-5m)"
        );
    }
}
