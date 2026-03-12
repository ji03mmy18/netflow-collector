use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::time::{interval, Duration};
use tracing::info;

pub struct Stats {
    pub received: AtomicU64,
    pub failed: AtomicU64,
    pub matched: AtomicU64,
    pub db_written: AtomicU64,
    pub db_failed: AtomicU64,
}

impl Stats {
    pub fn new() -> Self {
        Self {
            received: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            matched: AtomicU64::new(0),
            db_written: AtomicU64::new(0),
            db_failed: AtomicU64::new(0),
        }
    }
}

/// Spawns a background task that logs a stats summary every 60 seconds.
/// Only emits a log line when there were parse failures OR DB write failures
/// in the interval (avoids noise during normal operation).
pub fn start_reporter(stats: Arc<Stats>) {
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(60));
        // Consume the initial immediate tick so the first report fires at t+60s.
        ticker.tick().await;

        let mut prev_received = 0u64;
        let mut prev_failed = 0u64;
        let mut prev_matched = 0u64;
        let mut prev_db_written = 0u64;
        let mut prev_db_failed = 0u64;

        loop {
            ticker.tick().await;

            let received = stats.received.load(Ordering::Relaxed);
            let failed = stats.failed.load(Ordering::Relaxed);
            let matched = stats.matched.load(Ordering::Relaxed);
            let db_written = stats.db_written.load(Ordering::Relaxed);
            let db_failed = stats.db_failed.load(Ordering::Relaxed);

            let delta_failed = failed - prev_failed;
            let delta_db_failed = db_failed - prev_db_failed;

            if delta_failed > 0 || delta_db_failed > 0 {
                info!(
                    total_received = received,
                    interval_received = received - prev_received,
                    interval_parse_failed = delta_failed,
                    interval_matched = matched - prev_matched,
                    interval_db_written = db_written - prev_db_written,
                    interval_db_failed = delta_db_failed,
                    "stats report"
                );
            }

            prev_received = received;
            prev_failed = failed;
            prev_matched = matched;
            prev_db_written = db_written;
            prev_db_failed = db_failed;
        }
    });
}
