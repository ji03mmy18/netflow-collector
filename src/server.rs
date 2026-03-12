use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use arc_swap::ArcSwap;
use chrono::Utc;
use netflow_parser::NetflowParser;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::error;

use crate::db::FlowRow;
use crate::filter::FilterConfig;
use crate::live::LiveRecord;
use crate::stats::Stats;
use crate::{parser, printer};

/// Main UDP receive loop.  Runs forever; never returns under normal operation.
pub async fn run(
    socket: UdpSocket,
    filter_config: Arc<ArcSwap<FilterConfig>>,
    stats: Arc<Stats>,
    direct_print: bool,
    color: bool,
    db_tx: Option<mpsc::Sender<FlowRow>>,
    live_tx: Option<mpsc::Sender<LiveRecord>>,
) {
    let mut buf = vec![0u8; 65535];
    let mut netflow_parser = NetflowParser::default();

    if direct_print {
        printer::print_header();
    }

    loop {
        let len = match socket.recv(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                error!("recv error: {}", e);
                continue;
            }
        };

        // Capture receive time once per UDP packet (shared by all flows in it).
        let received_at = Utc::now();

        stats.received.fetch_add(1, Ordering::Relaxed);

        let parsed = parser::parse(&mut netflow_parser, &buf[..len]);

        if parsed.has_error {
            stats.failed.fetch_add(1, Ordering::Relaxed);
        }

        if parsed.flows.is_empty() {
            continue;
        }

        let fc = filter_config.load();

        for flow in &parsed.flows {
            let src_ip = u32::from(flow.src_addr);
            let dst_ip = u32::from(flow.dst_addr);

            let result = fc.check(src_ip, dst_ip);
            if !result.is_match() {
                continue;
            }

            stats.matched.fetch_add(1, Ordering::Relaxed);

            if direct_print {
                let ctx = printer::PrintContext {
                    color,
                    src_matched: result.src_matched,
                    dst_matched: result.dst_matched,
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
                    src_matched: result.src_matched,
                    dst_matched: result.dst_matched,
                };
                // Best-effort: drop on full channel (live display is non-critical).
                let _ = tx.try_send(rec);
            }

            if let Some(ref tx) = db_tx {
                let row = FlowRow {
                    received_at,
                    src_addr: IpAddr::V4(flow.src_addr),
                    src_port: flow.src_port as i32,
                    dst_addr: IpAddr::V4(flow.dst_addr),
                    dst_port: flow.dst_port as i32,
                    protocol: flow.protocol_number as i16,
                    packets: flow.d_pkts as i64,
                    bytes: flow.d_octets as i64,
                };
                if tx.try_send(row).is_err() {
                    // Channel full or closed — count as DB failure.
                    stats.db_failed.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}
