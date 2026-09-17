use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::{bail, Context};
use chrono::{DateTime, Duration as ChronoDuration, NaiveDate, Utc};
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tokio_postgres::types::ToSql;
use tokio_postgres::{Client, NoTls};
use tracing::{info, warn};

use crate::aggregator::{Counters, DayDelta, StatDelta, StatKey, BUCKET_SECONDS};
use crate::config::DatabaseConfig;
use crate::stats::Stats;

const BATCH_SIZE: usize = 1000;
const FLUSH_INTERVAL_SECS: u64 = 5;

/// Rows per statement when upserting statistics.  PostgreSQL caps a statement
/// at 65535 bind parameters; at 6 per row this leaves a wide margin even when a
/// flush carries several buckets at once.
const UPSERT_CHUNK_ROWS: usize = 2000;

/// A single NetFlow v5 record to be persisted.
pub struct FlowRow {
    pub ts: DateTime<Utc>,
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub src_port: i32,
    pub dst_port: i32,
    pub protocol: i16,
    pub packets: i64,
    pub bytes: i64,
    pub tcp_flags: i16,
    pub input: i32,
    pub output: i32,
    pub tos: i16,
    pub sampling_interval: i32,
}

/// One row of `collector_health_1m` — the answer to "how much can I trust the
/// numbers for this window".
#[derive(Default, Clone, Copy, Debug)]
pub struct HealthRow {
    pub bucket: Option<DateTime<Utc>>,
    pub packets_received: i64,
    pub flows_parsed: i64,
    pub parse_failures: i64,
    pub seq_gap: i64,
    pub flows_matched: i64,
    pub rows_written: i64,
    pub db_failures: i64,
    pub clock_skew_min_ms: Option<i64>,
    pub clock_skew_max_ms: Option<i64>,
    pub clock_skew_last_ms: Option<i64>,
    pub clock_skew_rejects: i64,
}

/// Everything produced by one flush of the in-memory aggregator.
pub struct FlushBatch {
    pub buckets: Vec<StatDelta>,
    pub days: Vec<DayDelta>,
    pub health: HealthRow,
}

/// Initial reconnect delay, doubling up to `RECONNECT_MAX_DELAY`.
const RECONNECT_BASE_DELAY_SECS: u64 = 1;
const RECONNECT_MAX_DELAY_SECS: u64 = 30;

/// A database connection that re-establishes itself.
///
/// Collector and database share a host, so the only way this link breaks is
/// PostgreSQL itself going away — a package upgrade, a crash, a planned
/// restart.  Two situations follow from that, and both are handled here by the
/// same retry loop:
///
/// * **Boot.** Both services start together and the collector wins the race
///   every time: PostgreSQL needs seconds to accept connections, the collector
///   fails in microseconds.  `After=postgresql.service` does not fix this — it
///   waits for the unit to start, not for the socket to answer.
/// * **Maintenance.** A restart mid-run would otherwise leave a live process
///   that never writes another row, because a `Client` is dead for good once its
///   connection drops.
///
/// Retrying forever is deliberate: the alternative is exiting, and a collector
/// that exits is one whose UDP socket is closed — and the in-memory statistics
/// for the outage are worth more than the raw rows lost while waiting.
pub struct Connection {
    cfg: DatabaseConfig,
    label: &'static str,
    client: Option<Client>,
}

impl Connection {
    pub fn new(cfg: DatabaseConfig, label: &'static str) -> Self {
        Self {
            cfg,
            label,
            client: None,
        }
    }

    /// A live client, waiting as long as it takes to get one.
    pub async fn get(&mut self) -> &mut Client {
        let mut delay = Duration::from_secs(RECONNECT_BASE_DELAY_SECS);
        let mut attempts = 0u32;
        // Distinguishes "reconnected" from "connected for the first time", so a
        // recovery is always visible in the log even when the retry succeeds on
        // the first try.
        let mut recovering = false;

        loop {
            if self.client.as_ref().is_some_and(|c| !c.is_closed()) {
                break;
            }
            if self.client.take().is_some() {
                recovering = true;
                warn!(label = self.label, "database connection lost");
            }

            match connect(&self.cfg).await {
                Ok(client) => {
                    if recovering || attempts > 0 {
                        info!(
                            label = self.label,
                            attempts, "database connection established"
                        );
                    }
                    self.client = Some(client);
                    break;
                }
                Err(e) => {
                    attempts += 1;
                    warn!(
                        label = self.label,
                        attempts,
                        retry_in_secs = delay.as_secs(),
                        error = %e,
                        "cannot reach the database; will retry"
                    );
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_secs(RECONNECT_MAX_DELAY_SECS));
                }
            }
        }

        self.client
            .as_mut()
            .expect("the loop only exits once a live client is stored")
    }
}

/// Connect to PostgreSQL.  The connection I/O task is spawned in the background.
pub async fn connect(cfg: &DatabaseConfig) -> anyhow::Result<Client> {
    let (client, connection) = tokio_postgres::connect(&cfg.connection_string(), NoTls)
        .await
        .context("failed to connect to PostgreSQL")?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            tracing::error!("DB connection error: {}", e);
        }
    });

    Ok(client)
}

/// Apply `sql/schema.sql`.  Every statement in it is idempotent, so this is
/// safe to re-run.
pub async fn migrate(client: &Client) -> anyhow::Result<()> {
    client
        .batch_execute(include_str!("../sql/schema.sql"))
        .await
        .context("migration failed")?;
    Ok(())
}

// ─── startup state ───────────────────────────────────────────────────────────

/// The intranet boundary, as `(network, mask)` in host byte order.
///
/// Kept `Copy` and free of the original text so the receive loop can carry it
/// by value; the text form is returned separately for logging and for the
/// recompute SQL, which needs a real `inet` literal.
#[derive(Clone, Copy, Debug)]
pub struct IntraCidr {
    pub network: u32,
    pub mask: u32,
}

impl IntraCidr {
    /// Is this address inside the intranet?
    #[inline]
    pub fn contains(&self, ip: u32) -> bool {
        ip & self.mask == self.network
    }
}

fn parse_cidr(s: &str) -> anyhow::Result<(u32, u32)> {
    let (ip_str, prefix) = match s.split_once('/') {
        Some((ip, p)) => (ip, p.parse::<u8>().context("invalid prefix length")?),
        None => (s, 32u8),
    };
    if prefix > 32 {
        bail!("prefix length {} > 32", prefix);
    }
    let ip: Ipv4Addr = ip_str.trim().parse().context("invalid IPv4 address")?;
    let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
    Ok((u32::from(ip) & mask, mask))
}

/// Parse the configured intranet CIDR.
pub fn parse_intra_cidr(text: &str) -> anyhow::Result<IntraCidr> {
    let (network, mask) = parse_cidr(text)
        .with_context(|| format!("[netflow].intra_cidr is not a valid IPv4 CIDR: '{}'", text))?;
    Ok(IntraCidr { network, mask })
}

/// Record the CIDR actually in use, and report the previous value if it differs.
///
/// The CIDR is configuration, not data — but which CIDR produced a given row *is*
/// data, and nothing in the statistics tables carries it.  Editing the config
/// silently changes what `intra_*` and `ext_*` mean from that moment on, which
/// months later reads as an unexplained step change in the reports.  One row and
/// one comparison is enough to turn that into a line in the log.
pub async fn record_intra_cidr(client: &Client, cidr: &str) -> anyhow::Result<Option<String>> {
    let previous: Option<String> = client
        .query_opt(
            "SELECT value FROM app_config WHERE key = 'intra_cidr_last_used'",
            &[],
        )
        .await
        .context("failed to read app_config — has the schema been applied? run --migrate first")?
        .map(|row| row.get(0));

    client
        .execute(
            "INSERT INTO app_config (key, value) VALUES ('intra_cidr_last_used', $1) \
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            &[&cidr],
        )
        .await
        .context("failed to record the intranet CIDR in use")?;

    Ok(previous.filter(|p| p != cidr))
}

// ─── raw writer ──────────────────────────────────────────────────────────────

/// Spawn the raw batch-writer task.
///
/// Flushes when 1000 rows have accumulated or 5 seconds have elapsed, whichever
/// comes first.  On failure the batch is discarded — the statistics path is
/// independent, so a database hiccup costs raw rows but not the running totals.
pub fn start_raw_writer(mut conn: Connection, mut rx: mpsc::Receiver<FlowRow>, stats: Arc<Stats>) {
    tokio::spawn(async move {
        let mut buffer: Vec<FlowRow> = Vec::with_capacity(BATCH_SIZE);
        let mut ticker = interval(Duration::from_secs(FLUSH_INTERVAL_SECS));
        ticker.tick().await; // consume the immediate first tick

        loop {
            tokio::select! {
                maybe_row = rx.recv() => {
                    match maybe_row {
                        Some(row) => {
                            buffer.push(row);
                            if buffer.len() >= BATCH_SIZE {
                                flush_raw(&mut conn, &mut buffer, &stats).await;
                            }
                        }
                        None => {
                            if !buffer.is_empty() {
                                flush_raw(&mut conn, &mut buffer, &stats).await;
                            }
                            return;
                        }
                    }
                }
                _ = ticker.tick() => {
                    if !buffer.is_empty() {
                        flush_raw(&mut conn, &mut buffer, &stats).await;
                    }
                }
            }
        }
    });
}

async fn flush_raw(conn: &mut Connection, buffer: &mut Vec<FlowRow>, stats: &Stats) {
    let count = buffer.len() as u64;
    // Waits for the database to come back if it is away.  Rows pile up in the
    // channel meanwhile and the receive loop drops them once it is full — raw is
    // the expendable half of the pipeline, and `collector_health_1m.db_failures`
    // records exactly how much went missing.
    let client = conn.get().await;
    match write_raw_rows(client, buffer).await {
        Ok(()) => {
            stats.db_written.fetch_add(count, Ordering::Relaxed);
        }
        Err(e) => {
            stats.db_failed.fetch_add(count, Ordering::Relaxed);
            warn!(rows = count, error = %e, "raw batch write failed, dropping batch");
        }
    }
    buffer.clear();
}

async fn write_raw_rows(client: &Client, rows: &[FlowRow]) -> anyhow::Result<()> {
    if rows.is_empty() {
        return Ok(());
    }

    const COLS: usize = 13;
    let mut query = String::from(
        "INSERT INTO flow_raw \
         (ts,srcaddr,dstaddr,srcport,dstport,prot,d_pkts,d_octets,\
          tcp_flags,input,output,tos,sampling_interval) VALUES ",
    );
    let mut params: Vec<&(dyn ToSql + Sync)> = Vec::with_capacity(rows.len() * COLS);

    for (i, row) in rows.iter().enumerate() {
        if i > 0 {
            query.push(',');
        }
        push_placeholders(&mut query, i * COLS, COLS);
        params.push(&row.ts);
        params.push(&row.src_addr);
        params.push(&row.dst_addr);
        params.push(&row.src_port);
        params.push(&row.dst_port);
        params.push(&row.protocol);
        params.push(&row.packets);
        params.push(&row.bytes);
        params.push(&row.tcp_flags);
        params.push(&row.input);
        params.push(&row.output);
        params.push(&row.tos);
        params.push(&row.sampling_interval);
    }

    client
        .execute(query.as_str(), &params)
        .await
        .context("flow_raw INSERT failed")?;
    Ok(())
}

fn push_placeholders(query: &mut String, base: usize, count: usize) {
    query.push('(');
    for k in 0..count {
        if k > 0 {
            query.push(',');
        }
        query.push('$');
        query.push_str(&(base + k + 1).to_string());
    }
    query.push(')');
}

// ─── statistics writer ───────────────────────────────────────────────────────

/// Beyond this many distinct `(bucket, addr)` pairs held across an outage, stop
/// taking on more.  A day of downtime at 3500 hosts is roughly 1M pairs, and
/// keeping what we already have beats discarding it to make room for newer data.
const CARRY_LIMIT: usize = 1_000_000;

/// Statistics that have not made it into the database yet.
///
/// Counters are additive, so a failed write does not have to be thrown away —
/// it is merged with whatever arrives next and retried on the following flush.
/// That is the whole reason this writer reconnects instead of the process
/// restarting: while the database is away the correct statistics are sitting in
/// memory, and a restart would discard them.  `flow_raw` gets a hole during an
/// outage; the statistics come out complete.
#[derive(Default)]
struct Carry {
    buckets: HashMap<(DateTime<Utc>, u32), Counters>,
    days: HashMap<(NaiveDate, u32), Counters>,
    health: Vec<HealthRow>,
    full: bool,
}

impl Carry {
    fn absorb(&mut self, batch: FlushBatch) {
        if self.buckets.len() >= CARRY_LIMIT || self.days.len() >= CARRY_LIMIT {
            if !self.full {
                self.full = true;
                warn!(
                    buckets = self.buckets.len(),
                    "undelivered statistics have hit the carry limit; \
                     further deltas are being dropped until the database returns"
                );
            }
            return;
        }

        for d in batch.buckets {
            self.buckets
                .entry((d.key.bucket, d.key.addr))
                .or_default()
                .add(&d.counters);
        }
        for d in batch.days {
            self.days
                .entry((d.day, d.addr))
                .or_default()
                .add(&d.counters);
        }
        if batch.health.bucket.is_some() {
            self.health.push(batch.health);
        }
    }

    fn is_empty(&self) -> bool {
        self.buckets.is_empty() && self.days.is_empty() && self.health.is_empty()
    }

    fn rows(&self) -> usize {
        self.buckets.len()
    }

    /// Flatten back into the shape the writer sends to PostgreSQL.
    fn to_batch(&self) -> FlushBatch {
        FlushBatch {
            buckets: self
                .buckets
                .iter()
                .map(|(&(bucket, addr), &counters)| StatDelta {
                    key: StatKey { bucket, addr },
                    counters,
                })
                .collect(),
            days: self
                .days
                .iter()
                .map(|(&(day, addr), &counters)| DayDelta {
                    day,
                    addr,
                    counters,
                })
                .collect(),
            health: HealthRow::default(),
        }
    }
}

/// Spawn the statistics writer.
///
/// Receives one batch per flush interval (a minute by default), so it is idle
/// almost all of the time.  It runs on its own connection so that a slow raw
/// insert can never delay the running totals, or vice versa.
pub fn start_stat_writer(
    mut conn: Connection,
    mut rx: mpsc::Receiver<FlushBatch>,
    stats: Arc<Stats>,
) {
    tokio::spawn(async move {
        let mut carry = Carry::default();

        while let Some(batch) = rx.recv().await {
            carry.absorb(batch);
            if carry.is_empty() {
                continue;
            }

            let pending = carry.to_batch();
            let health = std::mem::take(&mut carry.health);
            let rows = carry.rows() as u64;

            let client = conn.get().await;
            match write_flush_batch(client, &pending, &health).await {
                Ok(()) => {
                    stats.stat_written.fetch_add(rows, Ordering::Relaxed);
                    carry = Carry::default();
                }
                Err(e) => {
                    stats.stat_failed.fetch_add(rows, Ordering::Relaxed);
                    // Put the health rows back; the counter deltas are still in
                    // `carry` untouched, so the next flush retries everything.
                    carry.health = health;
                    warn!(
                        rows,
                        error = %e,
                        "statistics flush failed; deltas retained and will be retried"
                    );
                }
            }
        }
    });
}

async fn write_flush_batch(
    client: &mut Client,
    batch: &FlushBatch,
    health: &[HealthRow],
) -> anyhow::Result<()> {
    let tx = client.transaction().await.context("BEGIN failed")?;

    for chunk in batch.buckets.chunks(UPSERT_CHUNK_ROWS) {
        let bound: Vec<(IpAddr,)> = chunk
            .iter()
            .map(|d| (IpAddr::V4(Ipv4Addr::from(d.key.addr)),))
            .collect();
        let mut query = String::from(
            "INSERT INTO flow_stat_5m \
             (bucket,addr,intra_rx_bytes,intra_tx_bytes,ext_rx_bytes,ext_tx_bytes) VALUES ",
        );
        let mut params: Vec<&(dyn ToSql + Sync)> = Vec::with_capacity(chunk.len() * 6);
        for (i, d) in chunk.iter().enumerate() {
            if i > 0 {
                query.push(',');
            }
            push_placeholders(&mut query, i * 6, 6);
            params.push(&d.key.bucket);
            params.push(&bound[i].0);
            params.push(&d.counters.intra_rx);
            params.push(&d.counters.intra_tx);
            params.push(&d.counters.ext_rx);
            params.push(&d.counters.ext_tx);
        }
        query.push_str(
            " ON CONFLICT (bucket,addr) DO UPDATE SET \
             intra_rx_bytes = flow_stat_5m.intra_rx_bytes + EXCLUDED.intra_rx_bytes,\
             intra_tx_bytes = flow_stat_5m.intra_tx_bytes + EXCLUDED.intra_tx_bytes,\
             ext_rx_bytes   = flow_stat_5m.ext_rx_bytes   + EXCLUDED.ext_rx_bytes,\
             ext_tx_bytes   = flow_stat_5m.ext_tx_bytes   + EXCLUDED.ext_tx_bytes",
        );
        tx.execute(query.as_str(), &params)
            .await
            .context("flow_stat_5m upsert failed")?;
    }

    for chunk in batch.days.chunks(UPSERT_CHUNK_ROWS) {
        let bound: Vec<(IpAddr,)> = chunk
            .iter()
            .map(|d| (IpAddr::V4(Ipv4Addr::from(d.addr)),))
            .collect();
        let mut query = String::from(
            "INSERT INTO flow_stat_1d \
             (day,addr,intra_rx_bytes,intra_tx_bytes,ext_rx_bytes,ext_tx_bytes) VALUES ",
        );
        let mut params: Vec<&(dyn ToSql + Sync)> = Vec::with_capacity(chunk.len() * 6);
        for (i, d) in chunk.iter().enumerate() {
            if i > 0 {
                query.push(',');
            }
            push_placeholders(&mut query, i * 6, 6);
            params.push(&d.day);
            params.push(&bound[i].0);
            params.push(&d.counters.intra_rx);
            params.push(&d.counters.intra_tx);
            params.push(&d.counters.ext_rx);
            params.push(&d.counters.ext_tx);
        }
        query.push_str(
            " ON CONFLICT (day,addr) DO UPDATE SET \
             intra_rx_bytes = flow_stat_1d.intra_rx_bytes + EXCLUDED.intra_rx_bytes,\
             intra_tx_bytes = flow_stat_1d.intra_tx_bytes + EXCLUDED.intra_tx_bytes,\
             ext_rx_bytes   = flow_stat_1d.ext_rx_bytes   + EXCLUDED.ext_rx_bytes,\
             ext_tx_bytes   = flow_stat_1d.ext_tx_bytes   + EXCLUDED.ext_tx_bytes",
        );
        tx.execute(query.as_str(), &params)
            .await
            .context("flow_stat_1d upsert failed")?;
    }

    for h in health {
        let Some(bucket) = h.bucket else { continue };
        tx.execute(
            "INSERT INTO collector_health_1m \
             (bucket,packets_received,flows_parsed,parse_failures,seq_gap,flows_matched,\
              rows_written,db_failures,clock_skew_min_ms,clock_skew_max_ms,\
              clock_skew_last_ms,clock_skew_rejects) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) \
             ON CONFLICT (bucket) DO UPDATE SET \
               packets_received = collector_health_1m.packets_received + EXCLUDED.packets_received,\
               flows_parsed     = collector_health_1m.flows_parsed     + EXCLUDED.flows_parsed,\
               parse_failures   = collector_health_1m.parse_failures   + EXCLUDED.parse_failures,\
               seq_gap          = collector_health_1m.seq_gap          + EXCLUDED.seq_gap,\
               flows_matched    = collector_health_1m.flows_matched    + EXCLUDED.flows_matched,\
               rows_written     = collector_health_1m.rows_written     + EXCLUDED.rows_written,\
               db_failures      = collector_health_1m.db_failures      + EXCLUDED.db_failures,\
               clock_skew_min_ms  = LEAST(collector_health_1m.clock_skew_min_ms, EXCLUDED.clock_skew_min_ms),\
               clock_skew_max_ms  = GREATEST(collector_health_1m.clock_skew_max_ms, EXCLUDED.clock_skew_max_ms),\
               clock_skew_last_ms = COALESCE(EXCLUDED.clock_skew_last_ms, collector_health_1m.clock_skew_last_ms),\
               clock_skew_rejects = collector_health_1m.clock_skew_rejects + EXCLUDED.clock_skew_rejects",
            &[
                &bucket,
                &h.packets_received,
                &h.flows_parsed,
                &h.parse_failures,
                &h.seq_gap,
                &h.flows_matched,
                &h.rows_written,
                &h.db_failures,
                &h.clock_skew_min_ms,
                &h.clock_skew_max_ms,
                &h.clock_skew_last_ms,
                &h.clock_skew_rejects,
            ],
        )
        .await
        .context("collector_health_1m upsert failed")?;
    }

    tx.commit().await.context("COMMIT failed")?;
    Ok(())
}

// ─── recompute ───────────────────────────────────────────────────────────────

/// Rebuild `flow_stat_5m` for `[from, to)` directly from `flow_raw`.
///
/// This is the repair path behind the whole design: the in-memory aggregation is
/// only ever a fast path for something that stays derivable from raw for as long
/// as raw is retained.
///
/// The delete is scoped to the addresses the filter currently selects.  Without
/// that scope, recomputing an old range after a host left the filter would
/// delete its historical rows and never put them back — today's filter says
/// nothing about who was being recorded back then.
pub async fn recompute_5m(
    client: &mut Client,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    cidr: &str,
    addresses: &HashSet<u32>,
) -> anyhow::Result<u64> {
    let tx = client.transaction().await.context("BEGIN failed")?;

    // Refuse to rebuild a range that raw no longer covers.
    //
    // This function deletes first and rebuilds from `flow_raw`.  Past the raw
    // retention window there is nothing to rebuild from, so the delete would
    // stand alone and silently destroy statistics that cannot be recovered —
    // turning the documented repair path into a data-loss path whenever someone
    // points it at a date that is a little too old.
    let raw_rows: i64 = tx
        .query_one(
            "SELECT count(*)::bigint FROM flow_raw WHERE ts >= $1 AND ts < $2",
            &[&from, &to],
        )
        .await
        .context("failed to check raw coverage for the range")?
        .get(0);

    if raw_rows == 0 {
        let existing: i64 = tx
            .query_one(
                "SELECT count(*)::bigint FROM flow_stat_5m WHERE bucket >= $1 AND bucket < $2",
                &[&from, &to],
            )
            .await
            .context("failed to check existing statistics for the range")?
            .get(0);
        bail!(
            "flow_raw holds no rows for {} .. {} (past the retention window, or the wrong range); \
             refusing to rebuild, because doing so would delete the {} existing statistics rows \
             and put nothing back",
            from,
            to,
            existing
        );
    }

    // A real table of addresses, not a list of ranges tested with `<<=`: with a
    // few thousand single addresses that predicate can only be a nested loop
    // (measured at 76s for an hour of raw data, against 74ms for the equality
    // join this gives).  ANALYZE so the planner knows how big it is.
    tx.batch_execute(
        "CREATE TEMP TABLE filter_addrs (addr inet PRIMARY KEY) ON COMMIT DROP",
    )
    .await
    .context("failed to create the temporary address table")?;

    let addrs: Vec<IpAddr> = addresses
        .iter()
        .map(|ip| IpAddr::V4(Ipv4Addr::from(*ip)))
        .collect();
    tx.execute(
        "INSERT INTO filter_addrs (addr) SELECT unnest($1::inet[])",
        &[&addrs],
    )
    .await
    .context("failed to populate the temporary address table")?;
    tx.batch_execute("ANALYZE filter_addrs")
        .await
        .context("ANALYZE failed")?;

    tx.execute(
        "DELETE FROM flow_stat_5m \
         WHERE bucket >= $1 AND bucket < $2 \
           AND addr IN (SELECT addr FROM filter_addrs)",
        &[&from, &to],
    )
    .await
    .context("failed to clear the range")?;

    // The bucket width is written from the same constant the live path uses.
    // Spelling it as a literal here instead would leave two definitions that
    // nothing forces to agree: changing the resolution on the Rust side would
    // still compile and still run, and the recompute would quietly re-bucket
    // whatever range it touched — right totals, wrong granularity, rows landing
    // outside the requested range, and exit code 0.
    let query = format!(
            "INSERT INTO flow_stat_5m \
               (bucket, addr, intra_rx_bytes, intra_tx_bytes, ext_rx_bytes, ext_tx_bytes) \
             SELECT bucket, addr, SUM(irxb), SUM(itxb), SUM(erxb), SUM(etxb) \
             FROM ( \
               SELECT time_bucket(make_interval(secs => {secs}), r.ts) AS bucket, \
                      r.srcaddr AS addr, \
                      0::bigint AS irxb, \
                      CASE WHEN r.dstaddr <<= $3::text::inet \
                           THEN r.d_octets * r.sampling_interval ELSE 0 END AS itxb, \
                      0::bigint AS erxb, \
                      CASE WHEN r.dstaddr <<= $3::text::inet \
                           THEN 0 ELSE r.d_octets * r.sampling_interval END AS etxb \
               FROM flow_raw r JOIN filter_addrs m ON m.addr = r.srcaddr \
               WHERE r.ts >= $1 AND r.ts < $2 \
               UNION ALL \
               SELECT time_bucket(make_interval(secs => {secs}), r.ts), \
                      r.dstaddr, \
                      CASE WHEN r.srcaddr <<= $3::text::inet \
                           THEN r.d_octets * r.sampling_interval ELSE 0 END, \
                      0::bigint, \
                      CASE WHEN r.srcaddr <<= $3::text::inet \
                           THEN 0 ELSE r.d_octets * r.sampling_interval END, \
                      0::bigint \
               FROM flow_raw r JOIN filter_addrs m ON m.addr = r.dstaddr \
               WHERE r.ts >= $1 AND r.ts < $2 \
             ) s \
             GROUP BY bucket, addr",
        secs = BUCKET_SECONDS
    );

    let inserted = tx
        .execute(query.as_str(), &[&from, &to, &cidr])
        .await
        .context("flow_stat_5m recompute insert failed")?;

    tx.commit().await.context("COMMIT failed")?;
    Ok(inserted)
}

pub struct RollupOutcome {
    pub rows: u64,
    pub bytes_before: i64,
    pub bytes_after: i64,
}

impl RollupOutcome {
    /// Non-zero means the incremental path lost or double-counted something
    /// during the day.  This difference is the only signal that would otherwise
    /// be invisible, so the caller logs it either way.
    pub fn drift(&self) -> i64 {
        self.bytes_after - self.bytes_before
    }
}

/// Rebuild one Asia/Taipei day of `flow_stat_1d` from `flow_stat_5m`.
///
/// Idempotent by construction (delete then insert), so it can be re-run at will.
pub async fn recompute_day(client: &mut Client, day: NaiveDate) -> anyhow::Result<RollupOutcome> {
    let (from, to) = taipei_day_bounds(day);

    let tx = client.transaction().await.context("BEGIN failed")?;

    let before: i64 = tx
        .query_one(
            "SELECT COALESCE(SUM(intra_rx_bytes+intra_tx_bytes+ext_rx_bytes+ext_tx_bytes),0)::bigint \
             FROM flow_stat_1d WHERE day = $1",
            &[&day],
        )
        .await
        .context("failed to read the existing day total")?
        .get(0);

    tx.execute("DELETE FROM flow_stat_1d WHERE day = $1", &[&day])
        .await
        .context("failed to clear the day")?;

    let rows = tx
        .execute(
            "INSERT INTO flow_stat_1d \
               (day, addr, intra_rx_bytes, intra_tx_bytes, ext_rx_bytes, ext_tx_bytes) \
             SELECT $1::date, addr, \
                    SUM(intra_rx_bytes), SUM(intra_tx_bytes), \
                    SUM(ext_rx_bytes),   SUM(ext_tx_bytes) \
             FROM flow_stat_5m \
             WHERE bucket >= $2 AND bucket < $3 \
             GROUP BY addr",
            &[&day, &from, &to],
        )
        .await
        .context("flow_stat_1d rollup insert failed")?;

    let after: i64 = tx
        .query_one(
            "SELECT COALESCE(SUM(intra_rx_bytes+intra_tx_bytes+ext_rx_bytes+ext_tx_bytes),0)::bigint \
             FROM flow_stat_1d WHERE day = $1",
            &[&day],
        )
        .await
        .context("failed to read the rebuilt day total")?
        .get(0);

    tx.commit().await.context("COMMIT failed")?;

    Ok(RollupOutcome {
        rows,
        bytes_before: before,
        bytes_after: after,
    })
}

/// The UTC half-open interval covering one Asia/Taipei calendar day.
pub fn taipei_day_bounds(day: NaiveDate) -> (DateTime<Utc>, DateTime<Utc>) {
    let local_midnight = day.and_hms_opt(0, 0, 0).expect("midnight always exists");
    let from = DateTime::<Utc>::from_naive_utc_and_offset(local_midnight, Utc) - ChronoDuration::hours(8);
    (from, from + ChronoDuration::days(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_parses_with_and_without_a_prefix() {
        let (net, mask) = parse_cidr("10.10.0.0/16").unwrap();
        assert_eq!(mask, 0xFFFF_0000);
        assert_eq!(net, u32::from(Ipv4Addr::new(10, 10, 0, 0)));

        let (net, mask) = parse_cidr("203.0.113.1").unwrap();
        assert_eq!(mask, u32::MAX);
        assert_eq!(net, u32::from(Ipv4Addr::new(203, 0, 113, 1)));
    }

    #[test]
    fn cidr_host_bits_are_masked_off() {
        let (net, _) = parse_cidr("10.10.5.7/16").unwrap();
        assert_eq!(net, u32::from(Ipv4Addr::new(10, 10, 0, 0)));
    }

    #[test]
    fn day_bounds_span_taipei_midnight_to_midnight() {
        let (from, to) = taipei_day_bounds(NaiveDate::from_ymd_opt(2026, 9, 15).unwrap());
        assert_eq!(from.to_rfc3339(), "2026-09-14T16:00:00+00:00");
        assert_eq!(to.to_rfc3339(), "2026-09-15T16:00:00+00:00");
    }
}
