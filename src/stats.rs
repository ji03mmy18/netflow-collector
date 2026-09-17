use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chrono::{DateTime, TimeZone, Utc};
use tokio::time::{interval, Duration};
use tracing::info;

use crate::db::HealthRow;

pub struct Stats {
    /// UDP packets received (not flow records).
    pub received: AtomicU64,
    pub failed: AtomicU64,
    /// Flow records parsed out of those packets.
    pub parsed: AtomicU64,
    /// Flow records whose src or dst is on the monitored list.
    pub matched: AtomicU64,
    /// Flow records estimated lost in transit, from flow_sequence gaps.
    pub seq_gap: AtomicU64,
    pub db_written: AtomicU64,
    pub db_failed: AtomicU64,
    pub stat_written: AtomicU64,
    pub stat_failed: AtomicU64,
}

impl Stats {
    pub fn new() -> Self {
        Self {
            received: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            parsed: AtomicU64::new(0),
            matched: AtomicU64::new(0),
            seq_gap: AtomicU64::new(0),
            db_written: AtomicU64::new(0),
            db_failed: AtomicU64::new(0),
            stat_written: AtomicU64::new(0),
            stat_failed: AtomicU64::new(0),
        }
    }
}

/// Spawns a background task that logs a stats summary every 60 seconds.
/// Only emits a log line when something went wrong in the interval — parse
/// failures, dropped flows, or database errors — so a healthy run stays quiet.
pub fn start_reporter(stats: Arc<Stats>) {
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(60));
        ticker.tick().await; // consume the immediate first tick

        let mut prev = Snapshot::take(&stats);

        loop {
            ticker.tick().await;
            let now = Snapshot::take(&stats);
            let d = now.since(&prev);

            if d.failed > 0 || d.seq_gap > 0 || d.db_failed > 0 || d.stat_failed > 0 {
                info!(
                    total_received = now.received,
                    interval_received = d.received,
                    interval_parse_failed = d.failed,
                    interval_seq_gap = d.seq_gap,
                    interval_matched = d.matched,
                    interval_db_written = d.db_written,
                    interval_db_failed = d.db_failed,
                    interval_stat_failed = d.stat_failed,
                    "stats report"
                );
            }

            prev = now;
        }
    });
}

#[derive(Clone, Copy, Default)]
struct Snapshot {
    received: u64,
    failed: u64,
    parsed: u64,
    matched: u64,
    seq_gap: u64,
    db_written: u64,
    db_failed: u64,
    stat_failed: u64,
}

impl Snapshot {
    fn take(stats: &Stats) -> Self {
        Self {
            received: stats.received.load(Ordering::Relaxed),
            failed: stats.failed.load(Ordering::Relaxed),
            parsed: stats.parsed.load(Ordering::Relaxed),
            matched: stats.matched.load(Ordering::Relaxed),
            seq_gap: stats.seq_gap.load(Ordering::Relaxed),
            db_written: stats.db_written.load(Ordering::Relaxed),
            db_failed: stats.db_failed.load(Ordering::Relaxed),
            stat_failed: stats.stat_failed.load(Ordering::Relaxed),
        }
    }

    fn since(&self, prev: &Snapshot) -> Snapshot {
        Snapshot {
            received: self.received - prev.received,
            failed: self.failed - prev.failed,
            parsed: self.parsed - prev.parsed,
            matched: self.matched - prev.matched,
            seq_gap: self.seq_gap - prev.seq_gap,
            db_written: self.db_written - prev.db_written,
            db_failed: self.db_failed - prev.db_failed,
            stat_failed: self.stat_failed - prev.stat_failed,
        }
    }
}

/// Detects flow records lost in transit.
///
/// The v5 header carries the exporter's cumulative count of flows sent, so a
/// jump larger than the previous packet's `count` is the number of records that
/// never arrived.  Without this the collector has no way at all to know it is
/// dropping data: UDP loss is silent, the totals simply come out low, and the
/// reports look entirely normal.
#[derive(Default)]
pub struct SequenceTracker {
    next_expected: Option<u32>,
}

impl SequenceTracker {
    /// Feed one v5 header; returns how many records are presumed lost.
    pub fn observe(&mut self, sequence: u32, count: u16) -> u64 {
        let gap = match self.next_expected {
            Some(expected) => {
                // wrapping_sub so the u32 counter's own rollover reads as zero
                // rather than as four billion lost records.
                let diff = sequence.wrapping_sub(expected);
                // A huge "gap" means reordering or an exporter restart, not loss.
                if diff > 0 && diff < SANE_GAP_LIMIT {
                    diff as u64
                } else {
                    0
                }
            }
            None => 0,
        };
        self.next_expected = Some(sequence.wrapping_add(count as u32));
        gap
    }
}

/// Above this, a sequence jump is far more likely to be a restart or a reorder
/// than genuine loss, and counting it would drown the real signal.
const SANE_GAP_LIMIT: u32 = 1_000_000;

/// Accumulates one flush window's worth of health data.
///
/// The counters that the receive loop owns are tracked directly; the ones the
/// writer tasks own are read from the shared atomics and differenced.
pub struct HealthAccumulator {
    packets_received: i64,
    flows_parsed: i64,
    parse_failures: i64,
    seq_gap: i64,
    flows_matched: i64,
    clock_skew_min_ms: Option<i64>,
    clock_skew_max_ms: Option<i64>,
    clock_skew_last_ms: Option<i64>,
    clock_skew_rejects: i64,
    prev_db_written: u64,
    prev_db_failed: u64,
}

impl HealthAccumulator {
    pub fn new(stats: &Stats) -> Self {
        Self {
            packets_received: 0,
            flows_parsed: 0,
            parse_failures: 0,
            seq_gap: 0,
            flows_matched: 0,
            clock_skew_min_ms: None,
            clock_skew_max_ms: None,
            clock_skew_last_ms: None,
            clock_skew_rejects: 0,
            prev_db_written: stats.db_written.load(Ordering::Relaxed),
            prev_db_failed: stats.db_failed.load(Ordering::Relaxed),
        }
    }

    pub fn packet(&mut self, parse_failed: bool) {
        self.packets_received += 1;
        if parse_failed {
            self.parse_failures += 1;
        }
    }

    pub fn flows(&mut self, parsed: usize, matched: usize) {
        self.flows_parsed += parsed as i64;
        self.flows_matched += matched as i64;
    }

    pub fn lost(&mut self, records: u64) {
        self.seq_gap += records as i64;
    }

    /// Record the observed `received_at - ts` for one flow.  In a healthy system
    /// this is a tight band a second or two wide; a sudden jump to hours is the
    /// exporter's clock breaking, and is visible here within the minute.
    pub fn clock_skew(&mut self, skew_ms: i64, rejected: bool) {
        self.clock_skew_last_ms = Some(skew_ms);
        self.clock_skew_min_ms = Some(match self.clock_skew_min_ms {
            Some(m) => m.min(skew_ms),
            None => skew_ms,
        });
        self.clock_skew_max_ms = Some(match self.clock_skew_max_ms {
            Some(m) => m.max(skew_ms),
            None => skew_ms,
        });
        if rejected {
            self.clock_skew_rejects += 1;
        }
    }

    /// Produce the row for this window and reset for the next one.
    pub fn take(&mut self, stats: &Stats, now: DateTime<Utc>) -> HealthRow {
        let db_written = stats.db_written.load(Ordering::Relaxed);
        let db_failed = stats.db_failed.load(Ordering::Relaxed);

        let row = HealthRow {
            bucket: Some(floor_to_minute(now)),
            packets_received: self.packets_received,
            flows_parsed: self.flows_parsed,
            parse_failures: self.parse_failures,
            seq_gap: self.seq_gap,
            flows_matched: self.flows_matched,
            rows_written: db_written.saturating_sub(self.prev_db_written) as i64,
            db_failures: db_failed.saturating_sub(self.prev_db_failed) as i64,
            clock_skew_min_ms: self.clock_skew_min_ms,
            clock_skew_max_ms: self.clock_skew_max_ms,
            clock_skew_last_ms: self.clock_skew_last_ms,
            clock_skew_rejects: self.clock_skew_rejects,
        };

        self.packets_received = 0;
        self.flows_parsed = 0;
        self.parse_failures = 0;
        self.seq_gap = 0;
        self.flows_matched = 0;
        self.clock_skew_min_ms = None;
        self.clock_skew_max_ms = None;
        self.clock_skew_last_ms = None;
        self.clock_skew_rejects = 0;
        self.prev_db_written = db_written;
        self.prev_db_failed = db_failed;

        row
    }
}

fn floor_to_minute(ts: DateTime<Utc>) -> DateTime<Utc> {
    let secs = ts.timestamp();
    Utc.timestamp_opt(secs - secs.rem_euclid(60), 0)
        .single()
        .unwrap_or(ts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contiguous_sequences_report_no_loss() {
        let mut t = SequenceTracker::default();
        assert_eq!(t.observe(1000, 30), 0); // first packet: nothing to compare
        assert_eq!(t.observe(1030, 30), 0);
        assert_eq!(t.observe(1060, 30), 0);
    }

    #[test]
    fn a_jump_counts_the_missing_records() {
        let mut t = SequenceTracker::default();
        t.observe(1000, 30);
        assert_eq!(t.observe(1080, 30), 50, "1030..1080 never arrived");
    }

    #[test]
    fn an_exporter_restart_is_not_counted_as_loss() {
        let mut t = SequenceTracker::default();
        t.observe(4_000_000_000, 30);
        assert_eq!(t.observe(0, 30), 0);
    }

    #[test]
    fn the_u32_counter_rollover_is_not_counted_as_loss() {
        let mut t = SequenceTracker::default();
        // Straddle the wrap: the expected sequence crosses 2^32 mid-stream, so a
        // plain subtraction here would read as ~4 billion records lost.
        t.observe(u32::MAX - 70, 100); // next expected wraps around to 29
        assert_eq!(t.observe(29, 30), 0);
        assert_eq!(t.observe(59, 30), 0);
    }
}
