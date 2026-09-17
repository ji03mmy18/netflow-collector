//! In-memory 5-minute bucket aggregation.
//!
//! Every matched flow contributes to one or two `(bucket, ip_id)` counters
//! rather than producing a statistics write of its own.  At a 1-second active
//! timeout a single conversation emits ~300 records per 5-minute bucket, so
//! folding them together here is the difference between ~600 statistics writes
//! per second and ~12.
//!
//! Counters hold the **delta since the last flush**, never a running total.
//! The database applies them with `+= EXCLUDED`, which is what makes late
//! records free: a flow arriving for a bucket that was already written just
//! adds another delta to the same key.  There is no grace period to tune and
//! no notion of a bucket being "closed".

use std::collections::HashMap;

use chrono::{DateTime, Duration, NaiveDate, TimeZone, Utc};

/// Bucket width for `flow_stat_5m`.  This is a data-model decision (it defines
/// the resolution of the curves you can plot) and is deliberately *not* tied to
/// the flush interval, which is an operational one.
pub const BUCKET_SECONDS: i64 = 300;

/// Taiwan has observed no DST since 1979, so a fixed offset is exact here and
/// avoids pulling in a timezone database.  It is also why no 5-minute bucket
/// ever straddles the day boundary: +08:00 is a whole number of hours.
const TAIPEI_OFFSET_HOURS: i64 = 8;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct StatKey {
    pub bucket: DateTime<Utc>,
    /// Host-order IPv4 of the monitored endpoint this row is written from the
    /// point of view of.
    pub addr: u32,
}

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct Counters {
    pub intra_rx: i64,
    pub intra_tx: i64,
    pub ext_rx: i64,
    pub ext_tx: i64,
}

impl Counters {
    fn is_zero(&self) -> bool {
        self.intra_rx == 0 && self.intra_tx == 0 && self.ext_rx == 0 && self.ext_tx == 0
    }

    pub fn add(&mut self, other: &Counters) {
        self.intra_rx += other.intra_rx;
        self.intra_tx += other.intra_tx;
        self.ext_rx += other.ext_rx;
        self.ext_tx += other.ext_tx;
    }
}

/// One `(bucket, ip_id)` delta ready to be written.
#[derive(Clone, Copy, Debug)]
pub struct StatDelta {
    pub key: StatKey,
    pub counters: Counters,
}

/// One `(day, ip_id)` delta, pre-folded from the 5-minute deltas.
///
/// This folding is not an optimisation — it is required.  A single flush can
/// carry several buckets of the same day for the same IP, and PostgreSQL
/// refuses to let one `INSERT ... ON CONFLICT DO UPDATE` touch the same row
/// twice.
#[derive(Clone, Copy, Debug)]
pub struct DayDelta {
    pub day: NaiveDate,
    pub addr: u32,
    pub counters: Counters,
}

#[derive(Default)]
pub struct Aggregator {
    pending: HashMap<StatKey, Counters>,
}

impl Aggregator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Traffic sent *by* the monitored IP.
    pub fn add_tx(&mut self, bucket: DateTime<Utc>, addr: u32, intra: bool, bytes: i64) {
        let c = self.pending.entry(StatKey { bucket, addr }).or_default();
        if intra {
            c.intra_tx += bytes;
        } else {
            c.ext_tx += bytes;
        }
    }

    /// Traffic received *by* the monitored IP.
    pub fn add_rx(&mut self, bucket: DateTime<Utc>, addr: u32, intra: bool, bytes: i64) {
        let c = self.pending.entry(StatKey { bucket, addr }).or_default();
        if intra {
            c.intra_rx += bytes;
        } else {
            c.ext_rx += bytes;
        }
    }

    /// Take everything accumulated so far, leaving the aggregator empty.
    ///
    /// Draining outright (rather than zeroing entries in place) is what keeps
    /// this bounded: nothing needs evicting, because a bucket only reappears if
    /// a record for it actually arrives.
    pub fn drain(&mut self) -> (Vec<StatDelta>, Vec<DayDelta>) {
        let mut bucket_deltas = Vec::with_capacity(self.pending.len());
        let mut by_day: HashMap<(NaiveDate, u32), Counters> = HashMap::new();

        for (key, counters) in self.pending.drain() {
            if counters.is_zero() {
                continue;
            }
            by_day
                .entry((taipei_day(key.bucket), key.addr))
                .or_default()
                .add(&counters);
            bucket_deltas.push(StatDelta { key, counters });
        }

        let day_deltas = by_day
            .into_iter()
            .map(|((day, addr), counters)| DayDelta {
                day,
                addr,
                counters,
            })
            .collect();

        (bucket_deltas, day_deltas)
    }
}

/// Floor a timestamp to its 5-minute bucket.
pub fn bucket_of(ts: DateTime<Utc>) -> DateTime<Utc> {
    let secs = ts.timestamp();
    // rem_euclid, not %, so pre-epoch timestamps floor downwards too.
    let floored = secs - secs.rem_euclid(BUCKET_SECONDS);
    Utc.timestamp_opt(floored, 0)
        .single()
        .unwrap_or_else(|| Utc.timestamp_opt(0, 0).unwrap())
}

/// The Asia/Taipei calendar day a bucket belongs to.
pub fn taipei_day(bucket: DateTime<Utc>) -> NaiveDate {
    (bucket + Duration::hours(TAIPEI_OFFSET_HOURS)).date_naive()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn buckets_floor_to_five_minutes() {
        assert_eq!(bucket_of(at("2026-09-15T10:04:59Z")), at("2026-09-15T10:00:00Z"));
        assert_eq!(bucket_of(at("2026-09-15T10:05:00Z")), at("2026-09-15T10:05:00Z"));
    }

    #[test]
    fn day_boundary_lands_on_taipei_midnight() {
        // 15:55 UTC is 23:55 in Taipei — still the 15th.
        assert_eq!(taipei_day(at("2026-09-15T15:55:00Z")).to_string(), "2026-09-15");
        // 16:00 UTC is 00:00 on the 16th in Taipei.
        assert_eq!(taipei_day(at("2026-09-15T16:00:00Z")).to_string(), "2026-09-16");
    }

    #[test]
    fn drain_folds_buckets_of_one_day_into_a_single_row() {
        let mut agg = Aggregator::new();
        agg.add_tx(at("2026-09-15T10:00:00Z"), 7, false, 100);
        agg.add_tx(at("2026-09-15T10:05:00Z"), 7, false, 250);
        agg.add_rx(at("2026-09-15T10:05:00Z"), 7, true, 30);

        let (buckets, days) = agg.drain();
        assert_eq!(buckets.len(), 2);
        assert_eq!(days.len(), 1, "both buckets are the same Taipei day");
        assert_eq!(days[0].counters.ext_tx, 350);
        assert_eq!(days[0].counters.intra_rx, 30);

        let (buckets, days) = agg.drain();
        assert!(buckets.is_empty() && days.is_empty(), "drain leaves nothing behind");
    }

    #[test]
    fn both_ends_monitored_produces_two_rows() {
        let mut agg = Aggregator::new();
        let b = at("2026-09-15T10:00:00Z");
        agg.add_tx(b, 1, true, 500); // sender's view
        agg.add_rx(b, 2, true, 500); // receiver's view
        let (buckets, _) = agg.drain();
        assert_eq!(buckets.len(), 2);
    }
}
