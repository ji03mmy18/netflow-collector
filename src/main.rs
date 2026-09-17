mod aggregator;
mod config;
mod db;
mod filter;
mod live;
mod parser;
mod printer;
mod server;
mod stats;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use arc_swap::ArcSwap;
use chrono::{DateTime, Duration, NaiveDate, Utc};
use clap::Parser;
use tokio::signal::unix::{signal, SignalKind};
use tracing::{error, info, warn};

use crate::stats::Stats;

#[derive(Parser, Debug)]
#[command(version, about = "NetFlow v5 collector — receives, filters, and prints/stores flow records")]
struct Args {
    /// UDP listen address and port, e.g. 0.0.0.0:2055
    /// (not required for --migrate or the recompute modes)
    #[arg(long)]
    bind: Option<String>,

    /// Config file path (TOML format)
    #[arg(long)]
    config: PathBuf,

    /// Append filtered flow records to stdout line-by-line (pipe-friendly).
    /// Incompatible with --live.
    #[arg(long, default_value_t = false, conflicts_with = "live")]
    direct_print: bool,

    /// Live monitor mode: fixed-area refresh with NPS counter and last N flows.
    /// Incompatible with --direct-print.
    #[arg(long, default_value_t = false, conflicts_with = "direct_print")]
    live: bool,

    /// Enable ANSI colour output (applies to both --direct-print and --live)
    #[arg(long, default_value_t = false)]
    color: bool,

    /// Store filtered flows in PostgreSQL and maintain the 5m/1d statistics
    /// (requires [database] and [netflow].intra_cidr in the config file)
    #[arg(long, default_value_t = false)]
    db_store: bool,

    /// Run database migration (create tables, hypertables and policies) then exit.
    #[arg(long, default_value_t = false)]
    migrate: bool,

    /// Rebuild one Asia/Taipei day of flow_stat_1d from flow_stat_5m, then exit.
    /// Pass a date, or give the flag alone for yesterday.  Idempotent — the
    /// intended way to run the nightly rollup from cron.
    #[arg(long, value_name = "YYYY-MM-DD", num_args = 0..=1, default_missing_value = "yesterday")]
    recompute_day: Option<String>,

    /// Rebuild flow_stat_5m from flow_raw for a time range, then exit.
    /// Format: "<from> <to>" as RFC3339 instants, e.g.
    /// --recompute-5m "2026-09-15T00:00:00Z 2026-09-15T01:00:00Z"
    #[arg(long, value_name = "FROM TO")]
    recompute_5m: Option<String>,

    /// UDP socket receive buffer size in bytes (default: system value)
    #[arg(long)]
    recv_buffer: Option<usize>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    // Config is required for every mode.
    let cfg = config::load(&args.config).map_err(|e| {
        error!("failed to load config: {}", e);
        e
    })?;

    // ── one-shot modes ────────────────────────────────────────────────────────
    if args.migrate {
        let client = db::connect(require_db(&cfg, "--migrate")?).await?;
        info!("applying schema");
        db::migrate(&client).await?;
        info!("migration completed successfully");
        return Ok(());
    }

    if let Some(ref spec) = args.recompute_day {
        let day = parse_day(spec)?;
        let mut client = db::connect(require_db(&cfg, "--recompute-day")?).await?;
        let outcome = db::recompute_day(&mut client, day).await?;
        // The difference between the incrementally maintained total and the one
        // rebuilt from 5m is the only visibility into deltas lost during the
        // day, so it is reported whether or not it is zero.
        info!(
            day = %day,
            rows = outcome.rows,
            bytes_before = outcome.bytes_before,
            bytes_after = outcome.bytes_after,
            drift = outcome.drift(),
            "daily rollup complete"
        );
        if outcome.drift() != 0 {
            warn!(
                day = %day,
                drift = outcome.drift(),
                "incremental daily totals disagreed with the 5m rollup; the rebuilt values now stand"
            );
        }
        return Ok(());
    }

    if let Some(ref spec) = args.recompute_5m {
        let (from, to) = parse_range(spec)?;
        let cidr_text = require_intra_cidr(&cfg, "--recompute-5m")?;
        // The same filter the collector matched with, enumerated for the join.
        let addresses = filter::build(&cfg)?.expand()?;
        let mut client = db::connect(require_db(&cfg, "--recompute-5m")?).await?;
        // Recomputing with a different CIDR rewrites history under new
        // semantics.  That is sometimes exactly what you want (a typo being
        // fixed), so warn rather than refuse.
        if let Some(previous) = db::record_intra_cidr(&client, &cidr_text).await? {
            warn!(
                previous = %previous,
                current = %cidr_text,
                "intranet CIDR differs from the one that produced this data; the range is being reclassified"
            );
        }
        let rows = db::recompute_5m(&mut client, from, to, &cidr_text, &addresses).await?;
        info!(
            from = %from, to = %to, intra_cidr = %cidr_text, rows,
            "flow_stat_5m rebuilt from flow_raw"
        );
        warn!("affected days of flow_stat_1d are now stale — re-run --recompute-day for each");
        return Ok(());
    }

    // ── normal server mode ────────────────────────────────────────────────────
    let bind = args.bind.as_deref().ok_or_else(|| {
        error!("--bind is required for normal operation");
        anyhow::anyhow!("--bind is required")
    })?;

    info!(bind, config = ?args.config, "starting netflow-collector");

    let initial_filter = filter::build(&cfg).map_err(|e| {
        error!("failed to build filter: {}", e);
        e
    })?;
    info!("config loaded successfully");

    let filter_config: Arc<ArcSwap<filter::FilterConfig>> =
        Arc::new(ArcSwap::from_pointee(initial_filter));

    let bind_addr: std::net::SocketAddr = bind.parse()?;
    let socket = bind_socket(bind_addr, args.recv_buffer).await?;
    info!(addr = %bind_addr, "UDP socket bound");

    let stats = Arc::new(Stats::new());
    stats::start_reporter(stats.clone());

    // ── optional live monitor ─────────────────────────────────────────────────
    let live_tx = if args.live {
        let (tx, rx) = tokio::sync::mpsc::channel::<live::LiveRecord>(512);
        live::start(rx, filter_config.clone(), stats.clone(), args.color);
        Some(tx)
    } else {
        None
    };

    // ── optional database pipeline ────────────────────────────────────────────
    let db_pipeline = if args.db_store {
        let db_cfg = require_db(&cfg, "--db-store")?;
        let netflow_cfg = cfg.netflow();
        let stats_cfg = cfg.stats();

        let cidr_text = require_intra_cidr(&cfg, "--db-store")?;
        let intra = db::parse_intra_cidr(&cidr_text)?;
        report_filter_scope(&filter_config.load(), &intra, &cidr_text);

        // Two connections, each of which re-establishes itself: a slow raw
        // insert can then never delay the running totals, or vice versa, and
        // neither is left permanently dead by a PostgreSQL restart.
        //
        // This first `get()` also covers the boot ordering race — at start-up
        // PostgreSQL is usually still a few seconds from accepting connections,
        // so the collector waits here rather than exiting.  The UDP socket is
        // already bound at this point, so the kernel buffers what arrives.
        info!("connecting to database");
        let raw_conn = db::Connection::new(db_cfg.clone(), "raw");
        let mut stat_conn = db::Connection::new(db_cfg.clone(), "stats");

        if let Some(previous) = db::record_intra_cidr(stat_conn.get().await, &cidr_text).await? {
            warn!(
                previous = %previous,
                current = %cidr_text,
                "intranet CIDR changed; intra_*/ext_* figures before and after this point are not comparable"
            );
        }

        info!("database connections established");

        let (raw_tx, raw_rx) = tokio::sync::mpsc::channel::<db::FlowRow>(10_000);
        db::start_raw_writer(raw_conn, raw_rx, stats.clone());

        let (flush_tx, flush_rx) = tokio::sync::mpsc::channel::<db::FlushBatch>(64);
        db::start_stat_writer(stat_conn, flush_rx, stats.clone());

        info!(
            sampling_interval = netflow_cfg.sampling_interval,
            flush_seconds = stats_cfg.flush_seconds,
            bucket_seconds = aggregator::BUCKET_SECONDS,
            clock_skew_threshold_seconds = netflow_cfg.clock_skew_threshold_seconds,
            "statistics pipeline started"
        );

        Some(server::DbPipeline {
            raw_tx,
            flush_tx,
            intra,
            sampling_interval: netflow_cfg.sampling_interval,
            clock_skew_threshold_ms: netflow_cfg.clock_skew_threshold_seconds * 1000,
            flush_seconds: stats_cfg.flush_seconds,
        })
    } else {
        None
    };

    // ── SIGHUP handler — atomically reload the display filter ─────────────────
    //
    // Reloads the filter, the highlighted ports and the live line count.
    //
    // The filter governs what is stored and counted as well as what is printed,
    // so reloading it mid-run changes the meaning of the 5-minute bucket that is
    // currently open — the first half counted one set of addresses, the second
    // another.  Harmless for a display tweak, worth a restart when changing who
    // is being accounted for.  `[netflow].intra_cidr` is read once at start-up
    // for the same reason, and does not reload at all.
    let filter_config_reload = filter_config.clone();
    let config_path = args.config.clone();
    tokio::spawn(async move {
        let mut sighup = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                error!("failed to register SIGHUP handler: {}", e);
                return;
            }
        };
        loop {
            sighup.recv().await;
            info!("SIGHUP received, reloading config");
            match config::load(&config_path) {
                Ok(new_cfg) => match filter::build(&new_cfg) {
                    Ok(new_filter) => {
                        filter_config_reload.store(Arc::new(new_filter));
                        info!("config reloaded successfully");
                    }
                    Err(e) => warn!("failed to build filter from new config: {}", e),
                },
                Err(e) => warn!("failed to reload config: {}", e),
            }
        }
    });

    let opts = server::RunOptions {
        direct_print: args.direct_print,
        color: args.color,
    };
    server::run(socket, filter_config, stats, opts, db_pipeline, live_tx).await;

    Ok(())
}

/// Warn about the one thing the filter cannot check for itself.
///
/// Every category name (`intra_tx`, `ext_rx`, …) is written from the point of
/// view of a host inside the intranet CIDR.  A filtered address outside it still
/// produces rows, but they read backwards — almost always a typo, never worth
/// refusing to collect over.
fn report_filter_scope(fc: &filter::FilterConfig, intra: &db::IntraCidr, cidr_text: &str) {
    match fc.expand() {
        Ok(addresses) => {
            let outside = addresses.iter().filter(|ip| !intra.contains(**ip)).count();
            info!(
                addresses = addresses.len(),
                intra_cidr = cidr_text,
                "filter loaded"
            );
            if addresses.is_empty() {
                warn!("the filter matches nothing — no flow will be stored or counted");
            }
            if outside > 0 {
                warn!(
                    count = outside,
                    intra_cidr = cidr_text,
                    "filtered addresses fall outside the intranet CIDR; their intra_*/ext_* labels \
                     will be misleading, but they are still being recorded"
                );
            }
        }
        Err(e) => warn!(error = %e, "could not enumerate the filter for the startup summary"),
    }
}

fn require_intra_cidr(cfg: &config::Config, flag: &str) -> anyhow::Result<String> {
    cfg.netflow().intra_cidr.ok_or_else(|| {
        error!("{} requires intra_cidr in the [netflow] section of the config file", flag);
        anyhow::anyhow!("[netflow].intra_cidr is missing")
    })
}

fn require_db<'a>(cfg: &'a config::Config, flag: &str) -> anyhow::Result<&'a config::DatabaseConfig> {
    cfg.database.as_ref().ok_or_else(|| {
        error!("{} requires a [database] section in the config file", flag);
        anyhow::anyhow!("[database] section missing")
    })
}

/// Accepts `YYYY-MM-DD`, or `yesterday` — the usual case when run from cron.
fn parse_day(spec: &str) -> anyhow::Result<NaiveDate> {
    if spec.eq_ignore_ascii_case("yesterday") {
        // "Yesterday" means the Taipei calendar day, matching flow_stat_1d.day.
        return Ok(aggregator::taipei_day(Utc::now()) - Duration::days(1));
    }
    NaiveDate::parse_from_str(spec.trim(), "%Y-%m-%d")
        .with_context(|| format!("expected YYYY-MM-DD or 'yesterday', got '{}'", spec))
}

/// Parses `"<from> <to>"` as two RFC3339 instants, aligned outwards to bucket
/// boundaries so a partial bucket is never half-rebuilt.
fn parse_range(spec: &str) -> anyhow::Result<(DateTime<Utc>, DateTime<Utc>)> {
    let mut parts = spec.split_whitespace();
    let from = parts
        .next()
        .context("expected two RFC3339 instants separated by a space")?;
    let to = parts
        .next()
        .context("expected two RFC3339 instants separated by a space")?;
    if parts.next().is_some() {
        anyhow::bail!("expected exactly two instants, got more");
    }

    let parse = |s: &str| -> anyhow::Result<DateTime<Utc>> {
        Ok(DateTime::parse_from_rfc3339(s)
            .with_context(|| format!("'{}' is not an RFC3339 instant", s))?
            .with_timezone(&Utc))
    };

    let from = aggregator::bucket_of(parse(from)?);
    let to_raw = parse(to)?;
    let to = {
        let floored = aggregator::bucket_of(to_raw);
        if floored == to_raw {
            floored
        } else {
            floored + Duration::seconds(aggregator::BUCKET_SECONDS)
        }
    };

    if to <= from {
        anyhow::bail!("the range is empty: {} .. {}", from, to);
    }
    Ok((from, to))
}

async fn bind_socket(
    addr: std::net::SocketAddr,
    recv_buffer: Option<usize>,
) -> anyhow::Result<tokio::net::UdpSocket> {
    if let Some(buf_size) = recv_buffer {
        use socket2::{Domain, Socket, Type};
        let domain = if addr.is_ipv6() {
            Domain::IPV6
        } else {
            Domain::IPV4
        };
        let s2 = Socket::new(domain, Type::DGRAM, None)?;
        s2.set_reuse_address(true)?;
        s2.bind(&addr.into())?;
        s2.set_recv_buffer_size(buf_size)?;

        // An unprivileged process cannot raise SO_RCVBUF above
        // net.core.rmem_max, and the kernel caps it silently — setsockopt still
        // reports success.  Since the whole point of the flag is absorbing
        // bursts, getting 208 KB when 8 MB was asked for should not be something
        // you discover from a packet-loss graph weeks later.
        //
        // Linux reports back twice the requested size (it reserves the extra for
        // bookkeeping), so only a readback *below* the request means capping.
        match s2.recv_buffer_size() {
            Ok(actual) if actual < buf_size => warn!(
                requested_bytes = buf_size,
                actual_bytes = actual,
                "the kernel capped the UDP receive buffer; raise net.core.rmem_max to at least the requested size"
            ),
            Ok(actual) => info!(requested_bytes = buf_size, actual_bytes = actual, "UDP receive buffer set"),
            Err(e) => warn!(error = %e, "could not read back the UDP receive buffer size"),
        }

        let std_sock: std::net::UdpSocket = s2.into();
        std_sock.set_nonblocking(true)?;
        Ok(tokio::net::UdpSocket::from_std(std_sock)?)
    } else {
        Ok(tokio::net::UdpSocket::bind(addr).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_expand_outwards_to_bucket_boundaries() {
        let (from, to) = parse_range("2026-09-15T10:02:00Z 2026-09-15T10:07:00Z").unwrap();
        assert_eq!(from.to_rfc3339(), "2026-09-15T10:00:00+00:00");
        assert_eq!(to.to_rfc3339(), "2026-09-15T10:10:00+00:00");
    }

    #[test]
    fn aligned_ranges_are_left_alone() {
        let (from, to) = parse_range("2026-09-15T10:00:00Z 2026-09-15T10:05:00Z").unwrap();
        assert_eq!(from.to_rfc3339(), "2026-09-15T10:00:00+00:00");
        assert_eq!(to.to_rfc3339(), "2026-09-15T10:05:00+00:00");
    }

    #[test]
    fn an_empty_range_is_rejected() {
        assert!(parse_range("2026-09-15T10:05:00Z 2026-09-15T10:00:00Z").is_err());
    }
}
