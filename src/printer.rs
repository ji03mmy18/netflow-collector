use std::collections::HashSet;
use std::net::Ipv4Addr;

// Column widths: max IPv4 is 15 chars, ports/counts fit within 10.
const IP_WIDTH: usize = 18;
const NUM_WIDTH: usize = 10;

// ANSI escape sequences — no external crate needed.
const YELLOW: &str = "\x1b[33m";
const BRIGHT_GREEN: &str = "\x1b[92m";
const RESET: &str = "\x1b[0m";

pub fn print_header() {
    println!(
        "{:<ip$}{:<num$}{:<ip$}{:<num$}{:<num$}{}",
        "SRC_IP",
        "SRC_PORT",
        "DST_IP",
        "DST_PORT",
        "PACKETS",
        "BYTES",
        ip = IP_WIDTH,
        num = NUM_WIDTH,
    );
}

/// Context passed to `print_flow` for colour decisions.
pub struct PrintContext<'a> {
    pub color: bool,
    pub src_matched: bool,
    pub dst_matched: bool,
    pub highlighted_ports: &'a HashSet<u16>,
}

pub fn print_flow(
    src_addr: Ipv4Addr,
    src_port: u16,
    dst_addr: Ipv4Addr,
    dst_port: u16,
    d_pkts: u32,
    d_octets: u32,
    ctx: &PrintContext<'_>,
) {
    if !ctx.color {
        println!(
            "{:<ip$}{:<num$}{:<ip$}{:<num$}{:<num$}{}",
            src_addr,
            src_port,
            dst_addr,
            dst_port,
            d_pkts,
            d_octets,
            ip = IP_WIDTH,
            num = NUM_WIDTH,
        );
        return;
    }

    // Pad first so ANSI codes don't interfere with column alignment.
    let src_ip = paint(format!("{:<w$}", src_addr, w = IP_WIDTH), YELLOW, ctx.src_matched);
    let dst_ip = paint(format!("{:<w$}", dst_addr, w = IP_WIDTH), YELLOW, ctx.dst_matched);
    let src_p = paint(
        format!("{:<w$}", src_port, w = NUM_WIDTH),
        BRIGHT_GREEN,
        ctx.highlighted_ports.contains(&src_port),
    );
    let dst_p = paint(
        format!("{:<w$}", dst_port, w = NUM_WIDTH),
        BRIGHT_GREEN,
        ctx.highlighted_ports.contains(&dst_port),
    );

    println!(
        "{}{}{}{}{:<w$}{}",
        src_ip,
        src_p,
        dst_ip,
        dst_p,
        d_pkts,
        d_octets,
        w = NUM_WIDTH,
    );
}

/// Wrap `s` with the given ANSI color code + reset when `apply` is true.
#[inline]
fn paint(s: String, color: &str, apply: bool) -> String {
    if apply {
        format!("{}{}{}", color, s, RESET)
    } else {
        s
    }
}
