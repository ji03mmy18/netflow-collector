use std::net::Ipv4Addr;

use netflow_parser::{NetflowPacket, NetflowParser};

pub struct FlowRecord {
    pub src_addr: Ipv4Addr,
    pub dst_addr: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub d_pkts: u32,
    pub d_octets: u32,
    pub protocol_number: u8,
}

pub struct ParseResult {
    pub flows: Vec<FlowRecord>,
    /// True if the packet buffer contained a parse error (corrupted / unsupported data).
    pub has_error: bool,
}

/// Parse a raw UDP payload with the given stateful `NetflowParser`.
/// Only NetFlow v5 records are extracted; other versions are silently skipped.
pub fn parse(parser: &mut NetflowParser, buf: &[u8]) -> ParseResult {
    let result = parser.parse_bytes(buf);
    let has_error = result.error.is_some();

    let mut flows = Vec::new();
    for packet in result.packets {
        if let NetflowPacket::V5(v5) = packet {
            for flow in v5.flowsets {
                flows.push(FlowRecord {
                    src_addr: flow.src_addr,
                    dst_addr: flow.dst_addr,
                    src_port: flow.src_port,
                    dst_port: flow.dst_port,
                    d_pkts: flow.d_pkts,
                    d_octets: flow.d_octets,
                    protocol_number: flow.protocol_number,
                });
            }
        }
    }

    ParseResult { flows, has_error }
}
