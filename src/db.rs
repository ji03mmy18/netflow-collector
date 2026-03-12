use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::Context;
use chrono::{DateTime, Utc};
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tokio_postgres::types::ToSql;
use tokio_postgres::{Client, NoTls};
use tracing::warn;

use crate::config::DatabaseConfig;
use crate::stats::Stats;

const BATCH_SIZE: usize = 1000;
const FLUSH_INTERVAL_SECS: u64 = 5;

/// A single NetFlow v5 record to be persisted.
pub struct FlowRow {
    pub received_at: DateTime<Utc>,
    pub src_addr: IpAddr,
    pub src_port: i32,
    pub dst_addr: IpAddr,
    pub dst_port: i32,
    pub protocol: i16,
    pub packets: i64,
    pub bytes: i64,
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

/// Create the `netflow_records` table and enable the TimescaleDB hypertable.
/// Idempotent — safe to run multiple times.
pub async fn migrate(client: &Client) -> anyhow::Result<()> {
    client
        .batch_execute(
            "CREATE EXTENSION IF NOT EXISTS timescaledb;

             CREATE TABLE IF NOT EXISTS netflow_records (
                 received_at  TIMESTAMPTZ  NOT NULL,
                 src_addr     INET         NOT NULL,
                 src_port     INTEGER      NOT NULL,
                 dst_addr     INET         NOT NULL,
                 dst_port     INTEGER      NOT NULL,
                 protocol     SMALLINT     NOT NULL,
                 packets      BIGINT       NOT NULL,
                 bytes        BIGINT       NOT NULL
             );

             SELECT create_hypertable(
                 'netflow_records', 'received_at',
                 if_not_exists => TRUE
             );",
        )
        .await
        .context("migration failed")?;
    Ok(())
}

/// Spawn the batch-writer task.
///
/// Flushes to the DB when either:
/// - `BATCH_SIZE` (1 000) rows have accumulated, or
/// - `FLUSH_INTERVAL_SECS` (5 s) have elapsed since the last flush.
///
/// On write failure the entire batch is discarded and `stats.db_failed` is
/// incremented by the number of dropped rows.
pub fn start_writer(client: Client, mut rx: mpsc::Receiver<FlowRow>, stats: Arc<Stats>) {
    tokio::spawn(async move {
        let mut buffer: Vec<FlowRow> = Vec::with_capacity(BATCH_SIZE);
        let mut ticker = interval(Duration::from_secs(FLUSH_INTERVAL_SECS));
        // Consume the initial immediate tick.
        ticker.tick().await;

        loop {
            tokio::select! {
                maybe_row = rx.recv() => {
                    match maybe_row {
                        Some(row) => {
                            buffer.push(row);
                            if buffer.len() >= BATCH_SIZE {
                                flush_batch(&client, &mut buffer, &stats).await;
                            }
                        }
                        None => {
                            // Channel closed — flush remaining rows and exit.
                            if !buffer.is_empty() {
                                flush_batch(&client, &mut buffer, &stats).await;
                            }
                            return;
                        }
                    }
                }
                _ = ticker.tick() => {
                    if !buffer.is_empty() {
                        flush_batch(&client, &mut buffer, &stats).await;
                    }
                }
            }
        }
    });
}

async fn flush_batch(client: &Client, buffer: &mut Vec<FlowRow>, stats: &Stats) {
    let count = buffer.len() as u64;
    match write_rows(client, buffer).await {
        Ok(()) => {
            stats.db_written.fetch_add(count, Ordering::Relaxed);
        }
        Err(e) => {
            stats.db_failed.fetch_add(count, Ordering::Relaxed);
            warn!(rows = count, error = %e, "DB batch write failed, dropping batch");
        }
    }
    buffer.clear();
}

/// Build and execute a multi-row `INSERT … VALUES ($1,…),($9,…),…` statement.
async fn write_rows(client: &Client, rows: &[FlowRow]) -> anyhow::Result<()> {
    if rows.is_empty() {
        return Ok(());
    }

    // Build the query string: INSERT … VALUES ($1,…,…,$8),($9,…,$16), …
    let mut query = String::from(
        "INSERT INTO netflow_records \
         (received_at,src_addr,src_port,dst_addr,dst_port,protocol,packets,bytes) VALUES ",
    );
    // Collect typed references; their lifetimes are tied to `rows`.
    let mut params: Vec<&(dyn ToSql + Sync)> = Vec::with_capacity(rows.len() * 8);

    for (i, row) in rows.iter().enumerate() {
        let b = i * 8;
        if i > 0 {
            query.push(',');
        }
        query.push_str(&format!(
            "(${},${},${},${},${},${},${},${})",
            b + 1,
            b + 2,
            b + 3,
            b + 4,
            b + 5,
            b + 6,
            b + 7,
            b + 8,
        ));
        params.push(&row.received_at);
        params.push(&row.src_addr);
        params.push(&row.src_port);
        params.push(&row.dst_addr);
        params.push(&row.dst_port);
        params.push(&row.protocol);
        params.push(&row.packets);
        params.push(&row.bytes);
    }

    client
        .execute(query.as_str(), &params)
        .await
        .context("INSERT failed")?;
    Ok(())
}
