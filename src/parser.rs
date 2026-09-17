use std::net::Ipv4Addr;

use chrono::{DateTime, TimeZone, Utc};
use netflow_parser::{NetflowPacket, NetflowParser};

/// One NetFlow v5 flow record, with the exporter's relative timestamps already
/// resolved to absolute time.
pub struct FlowRecord {
    /// Flow end time, derived from the packet (see `flow_end_time`).
    pub ts: DateTime<Utc>,
    pub src_addr: Ipv4Addr,
    pub dst_addr: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub d_pkts: u32,
    pub d_octets: u32,
    pub protocol_number: u8,
    pub tcp_flags: u8,
    pub input: u16,
    pub output: u16,
    pub tos: u8,
}

pub struct ParseResult {
    pub flows: Vec<FlowRecord>,
    /// True if the packet buffer contained a parse error (corrupted / unsupported data).
    pub has_error: bool,
    /// `(flow_sequence, count)` of every v5 header seen, for gap detection.
    pub sequences: Vec<(u32, u16)>,
}

/// Resolve a v5 flow's end time to absolute UTC.
///
/// ```text
/// ts = (unix_secs, unix_nsecs) - (sys_up_time - last)
///        ^ absolute anchor        ^ relative delta
/// ```
///
/// The two halves have very different trustworthiness.  The delta is measured
/// entirely by the exporter's monotonic uptime counter and is correct no matter
/// what its wall clock says; only the anchor depends on the switch's NTP.  The
/// caller cross-checks the result against the collector's own receive time.
///
/// `sys_up_time`, `first` and `last` are u32 milliseconds and therefore roll
/// over every 2^32 ms ≈ 49.71 days.  A core switch stays up for years, so this
/// happens roughly seven times a year — `wrapping_sub` gives the correct delta
/// on both sides of the rollover as long as the true delta is under 49.7 days,
/// which at a 1-second active timeout it always is.
fn flow_end_time(base: DateTime<Utc>, sys_up_time: u32, last: u32) -> DateTime<Utc> {
    let delta_ms = sys_up_time.wrapping_sub(last);
    base - chrono::Duration::milliseconds(delta_ms as i64)
}

/// Export time from a v5 header.  Returns `None` if the device wrote something
/// that is not a representable instant.
fn export_time(unix_secs: u32, unix_nsecs: u32) -> Option<DateTime<Utc>> {
    // Some platforms leave unix_nsecs at 0 or fill it with junk; sub-second
    // precision is irrelevant at a 5-minute bucket width, so clamp rather than
    // discard the whole packet.
    let nsecs = if unix_nsecs < 1_000_000_000 { unix_nsecs } else { 0 };
    Utc.timestamp_opt(unix_secs as i64, nsecs).single()
}

/// Parse a raw UDP payload with the given stateful `NetflowParser`.
/// Only NetFlow v5 records are extracted; other versions are silently skipped.
pub fn parse(parser: &mut NetflowParser, buf: &[u8]) -> ParseResult {
    let result = parser.parse_bytes(buf);
    let mut has_error = result.error.is_some();

    let mut flows = Vec::new();
    let mut sequences = Vec::new();

    for packet in result.packets {
        let NetflowPacket::V5(v5) = packet else {
            continue;
        };

        let Some(base) = export_time(v5.header.unix_secs, v5.header.unix_nsecs) else {
            // Unusable header timestamp — every flow in this packet would land
            // on a garbage bucket, so drop the packet and let it show up in the
            // parse-failure counter.
            has_error = true;
            continue;
        };

        sequences.push((v5.header.flow_sequence, v5.header.count));

        for flow in v5.flowsets {
            flows.push(FlowRecord {
                ts: flow_end_time(base, v5.header.sys_up_time, flow.last),
                src_addr: flow.src_addr,
                dst_addr: flow.dst_addr,
                src_port: flow.src_port,
                dst_port: flow.dst_port,
                d_pkts: flow.d_pkts,
                d_octets: flow.d_octets,
                protocol_number: flow.protocol_number,
                tcp_flags: flow.tcp_flags,
                input: flow.input,
                output: flow.output,
                tos: flow.tos,
            });
        }
    }

    ParseResult {
        flows,
        has_error,
        sequences,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn end_time_subtracts_the_delta() {
        let base = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        // Flow ended 1200 ms before the packet was exported.
        let ts = flow_end_time(base, 5_000_000, 4_998_800);
        assert_eq!(ts, base - chrono::Duration::milliseconds(1200));
    }

    #[test]
    fn end_time_survives_the_49_day_rollover() {
        let base = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        // sys_up_time has just wrapped past 2^32; `last` has not yet.
        let last = u32::MAX - 295; // 4_294_967_000
        let sys_up_time = 500u32;
        // True elapsed: 296 ms to the wrap, then 500 ms after it.
        let ts = flow_end_time(base, sys_up_time, last);
        assert_eq!(ts, base - chrono::Duration::milliseconds(796));
    }

    #[test]
    fn junk_nanoseconds_are_clamped_not_fatal() {
        assert!(export_time(1_700_000_000, 4_000_000_000).is_some());
    }
}
