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

use arc_swap::ArcSwap;
use clap::Parser;
use tokio::signal::unix::{signal, SignalKind};
use tracing::{error, info, warn};

use crate::stats::Stats;

#[derive(Parser, Debug)]
#[command(version, about = "NetFlow v5 collector — receives, filters, and prints/stores flow records")]
struct Args {
    /// UDP listen address and port, e.g. 0.0.0.0:2055
    /// (not required when using --migrate)
    #[arg(long)]
    bind: Option<String>,

    /// Config file path (TOML format)
    #[arg(long)]
    config: PathBuf,

    /// Append filtered flow records to stdout line-by-line (pipe-friendly).
    /// Incompatible with --live.
    #[arg(long, default_value_t = false, conflicts_with = "live")]
    direct_print: bool,

    /// Live monitor mode: fixed-area refresh with NPS counter and last 10 flows.
    /// Incompatible with --direct-print.
    #[arg(long, default_value_t = false, conflicts_with = "direct_print")]
    live: bool,

    /// Enable ANSI colour output (applies to both --direct-print and --live)
    #[arg(long, default_value_t = false)]
    color: bool,

    /// Write filtered flow records to PostgreSQL (requires [database] in config)
    #[arg(long, default_value_t = false)]
    db_store: bool,

    /// Run database migration (create table + hypertable) then exit.
    /// Requires [database] section in config; --bind is not needed.
    #[arg(long, default_value_t = false)]
    migrate: bool,

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

    // Load config (required for all modes).
    let cfg = config::load(&args.config).map_err(|e| {
        error!("failed to load config: {}", e);
        e
    })?;

    // ── migrate mode ──────────────────────────────────────────────────────────
    if args.migrate {
        let db_cfg = cfg.database.as_ref().ok_or_else(|| {
            error!("--migrate requires a [database] section in the config file");
            anyhow::anyhow!("[database] section missing")
        })?;
        info!("connecting to database for migration");
        let client = db::connect(db_cfg).await?;
        db::migrate(&client).await?;
        info!("migration completed successfully");
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

    // Bind UDP socket (optionally with a custom SO_RCVBUF).
    let bind_addr: std::net::SocketAddr = bind.parse()?;
    let socket = bind_socket(bind_addr, args.recv_buffer).await?;
    info!(addr = %bind_addr, "UDP socket bound");

    // Stats reporter.
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

    // ── optional DB writer ────────────────────────────────────────────────────
    let db_tx = if args.db_store {
        let db_cfg = cfg.database.as_ref().ok_or_else(|| {
            error!("--db-store requires a [database] section in the config file");
            anyhow::anyhow!("[database] section missing")
        })?;
        info!("connecting to database");
        let client = db::connect(db_cfg).await?;
        info!("database connection established");
        let (tx, rx) = tokio::sync::mpsc::channel::<db::FlowRow>(10_000);
        db::start_writer(client, rx, stats.clone());
        Some(tx)
    } else {
        None
    };

    // ── SIGHUP handler — atomically reload filter config ─────────────────────
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

    // ── main receive loop ─────────────────────────────────────────────────────
    server::run(socket, filter_config, stats, args.direct_print, args.color, db_tx, live_tx).await;

    Ok(())
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
        let std_sock: std::net::UdpSocket = s2.into();
        std_sock.set_nonblocking(true)?;
        Ok(tokio::net::UdpSocket::from_std(std_sock)?)
    } else {
        Ok(tokio::net::UdpSocket::bind(addr).await?)
    }
}
