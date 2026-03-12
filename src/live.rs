use std::collections::{HashSet, VecDeque};
use std::io::Write;
use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};

use crate::filter::FilterConfig;
use crate::stats::Stats;

/// Number of ═ characters inside the box frame; total box width = BOX_INNER + 2.
const BOX_INNER: usize = 66;

const YELLOW: &str = "\x1b[33m";
const BRIGHT_GREEN: &str = "\x1b[92m";
const RESET: &str = "\x1b[0m";

/// A matched flow record forwarded to the live display task.
pub struct LiveRecord {
    pub src_addr: Ipv4Addr,
    pub src_port: u16,
    pub dst_addr: Ipv4Addr,
    pub dst_port: u16,
    pub d_pkts: u32,
    pub d_octets: u32,
    pub src_matched: bool,
    pub dst_matched: bool,
}

/// Spawn the live-monitor rendering task.
///
/// Redraws the terminal screen:
/// - on every new matched flow received through `rx`, and
/// - every 1 second (to refresh the NPS counter).
pub fn start(
    mut rx: mpsc::Receiver<LiveRecord>,
    filter_config: Arc<ArcSwap<FilterConfig>>,
    stats: Arc<Stats>,
    color: bool,
) {
    tokio::spawn(async move {
        let mut ring_size = filter_config.load().live_lines;
        let mut ring: VecDeque<LiveRecord> = VecDeque::with_capacity(ring_size + 1);

        let mut nps_ticker = interval(Duration::from_secs(1));
        // Consume the initial immediate tick so the first NPS update fires at t+1 s.
        nps_ticker.tick().await;

        let mut prev_matched = stats.matched.load(Ordering::Relaxed);
        let mut nps = 0u64;

        // Clear the screen once at startup, then home the cursor.
        print!("\x1b[2J\x1b[H");
        std::io::stdout().flush().ok();

        loop {
            tokio::select! {
                maybe_rec = rx.recv() => {
                    match maybe_rec {
                        Some(rec) => {
                            let fc = filter_config.load();
                            apply_resize(&mut ring, &mut ring_size, fc.live_lines);
                            if ring.len() >= ring_size {
                                ring.pop_front();
                            }
                            ring.push_back(rec);
                            redraw(&ring, ring_size, &stats, nps, color, &fc.highlighted_ports);
                        }
                        None => return, // sender dropped — exit task
                    }
                }
                _ = nps_ticker.tick() => {
                    let curr = stats.matched.load(Ordering::Relaxed);
                    nps = curr - prev_matched;
                    prev_matched = curr;
                    let fc = filter_config.load();
                    apply_resize(&mut ring, &mut ring_size, fc.live_lines);
                    redraw(&ring, ring_size, &stats, nps, color, &fc.highlighted_ports);
                }
            }
        }
    });
}

/// Redraw the entire live display in one buffered write.
///
/// Layout (15 lines total):
///   ╔══...══╗
///   NetFlow Live Monitor
///   NPS / Total / Filtered stats
///   ╚══...══╝
///   Column header
///   ─ up to 10 flow rows (padded with blank lines if fewer) ─
fn apply_resize(ring: &mut VecDeque<LiveRecord>, ring_size: &mut usize, new_size: usize) {
    if new_size == *ring_size {
        return;
    }
    *ring_size = new_size;
    while ring.len() > new_size {
        ring.pop_front();
    }
}

fn redraw(
    ring: &VecDeque<LiveRecord>,
    ring_size: usize,
    stats: &Stats,
    nps: u64,
    color: bool,
    highlighted_ports: &HashSet<u16>,
) {
    let total = stats.received.load(Ordering::Relaxed);
    let filtered = stats.matched.load(Ordering::Relaxed);

    let eq = "═".repeat(BOX_INNER);
    let mut buf = String::with_capacity(4096);

    // Home cursor — redraw over the same region every time.
    buf.push_str("\x1b[H");

    // ── Header box ──────────────────────────────────────────────────────────
    buf.push_str(&format!("╔{}╗\x1b[K\n", eq));
    buf.push_str("  NetFlow Live Monitor\x1b[K\n");
    buf.push_str(&format!(
        "  NPS: {:<12}Total: {:<16}Filtered: {}\x1b[K\n",
        fmt_commas(nps),
        fmt_commas(total),
        fmt_commas(filtered),
    ));
    buf.push_str(&format!("╚{}╝\x1b[K\n", eq));

    // ── Column header ───────────────────────────────────────────────────────
    buf.push_str(&format!(
        "{:<18}{:<10}{:<18}{:<10}{:<10}{}\x1b[K\n",
        "SRC_IP", "SRC_PORT", "DST_IP", "DST_PORT", "PACKETS", "BYTES"
    ));

    // ── Flow rows — always output exactly RING_SIZE lines ───────────────────
    for rec in ring.iter() {
        buf.push_str(&format_flow_line(rec, color, highlighted_ports));
        buf.push_str("\x1b[K\n");
    }
    // Fill any remaining slots with blank lines so stale text is wiped.
    for _ in ring.len()..ring_size {
        buf.push_str("\x1b[K\n");
    }

    print!("{}", buf);
    std::io::stdout().flush().ok();
}

fn format_flow_line(
    rec: &LiveRecord,
    color: bool,
    highlighted_ports: &HashSet<u16>,
) -> String {
    if !color {
        return format!(
            "{:<18}{:<10}{:<18}{:<10}{:<10}{}",
            rec.src_addr, rec.src_port, rec.dst_addr, rec.dst_port,
            rec.d_pkts, rec.d_octets,
        );
    }

    // Pad first, then wrap with colour codes so column widths stay correct.
    let src_ip = paint(format!("{:<18}", rec.src_addr), YELLOW, rec.src_matched);
    let dst_ip = paint(format!("{:<18}", rec.dst_addr), YELLOW, rec.dst_matched);
    let src_p = paint(
        format!("{:<10}", rec.src_port),
        BRIGHT_GREEN,
        highlighted_ports.contains(&rec.src_port),
    );
    let dst_p = paint(
        format!("{:<10}", rec.dst_port),
        BRIGHT_GREEN,
        highlighted_ports.contains(&rec.dst_port),
    );
    format!(
        "{}{}{}{}{:<10}{}",
        src_ip, src_p, dst_ip, dst_p, rec.d_pkts, rec.d_octets,
    )
}

/// Format a u64 with comma thousand separators, e.g. 1_234_567 → "1,234,567".
fn fmt_commas(n: u64) -> String {
    let s = n.to_string();
    let chars: Vec<char> = s.chars().collect();
    let len = chars.len();
    let mut out = String::with_capacity(len + len / 3);
    for (i, &c) in chars.iter().enumerate() {
        if i > 0 && (len - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

#[inline]
fn paint(s: String, color: &str, apply: bool) -> String {
    if apply {
        format!("{}{}{}", color, s, RESET)
    } else {
        s
    }
}
