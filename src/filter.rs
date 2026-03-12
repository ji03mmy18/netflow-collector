use std::collections::HashSet;
use std::net::Ipv4Addr;

use anyhow::{bail, Context};

use crate::config::{Config, HighlightedPortsConfig};

/// Built-in well-known ports highlighted in green when `--color` is active.
pub const DEFAULT_HIGHLIGHTED_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 8080,
];

/// Per-flow match result: tracks which side(s) triggered the filter.
pub struct MatchResult {
    pub src_matched: bool,
    pub dst_matched: bool,
}

impl MatchResult {
    #[inline]
    pub fn is_match(&self) -> bool {
        self.src_matched || self.dst_matched
    }
}

#[derive(Debug, Default)]
pub struct FilterGroup {
    exact: HashSet<u32>,
    cidrs: Vec<(u32, u32)>, // (network_addr, mask)
}

impl FilterGroup {
    pub fn matches(&self, ip: u32) -> bool {
        if self.exact.contains(&ip) {
            return true;
        }
        for &(network, mask) in &self.cidrs {
            if ip & mask == network {
                return true;
            }
        }
        false
    }

    fn add(&mut self, cidr: &str) -> anyhow::Result<()> {
        if let Some((ip_str, prefix_str)) = cidr.split_once('/') {
            let ip: Ipv4Addr = ip_str
                .parse()
                .with_context(|| format!("invalid IP address '{}'", ip_str))?;
            let prefix: u8 = prefix_str
                .parse()
                .with_context(|| format!("invalid prefix length '{}'", prefix_str))?;
            if prefix > 32 {
                bail!("prefix length {} > 32", prefix);
            }
            if prefix == 32 {
                self.exact.insert(u32::from(ip));
            } else {
                let mask = if prefix == 0 { 0u32 } else { !0u32 << (32 - prefix) };
                let network = u32::from(ip) & mask;
                self.cidrs.push((network, mask));
            }
        } else {
            let ip: Ipv4Addr = cidr
                .parse()
                .with_context(|| format!("invalid IP address '{}'", cidr))?;
            self.exact.insert(u32::from(ip));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct FilterConfig {
    src_only: FilterGroup,
    dst_only: FilterGroup,
    any: FilterGroup,
    /// Port set used for green highlighting in `--color` mode.
    pub highlighted_ports: HashSet<u16>,
    /// Ring buffer row count for `--live` mode (from `[live].lines`, default 10).
    pub live_lines: usize,
}

impl FilterConfig {
    /// Returns which side(s) of the flow matched the configured filter rules.
    /// Call `.is_match()` on the result to decide whether to output the flow.
    pub fn check(&self, src: u32, dst: u32) -> MatchResult {
        MatchResult {
            src_matched: self.src_only.matches(src) || self.any.matches(src),
            dst_matched: self.dst_only.matches(dst) || self.any.matches(dst),
        }
    }

}

pub fn build(config: &Config) -> anyhow::Result<FilterConfig> {
    let mut fc = FilterConfig {
        src_only: FilterGroup::default(),
        dst_only: FilterGroup::default(),
        any: FilterGroup::default(),
        highlighted_ports: build_port_set(config.highlighted_ports.as_ref()),
        live_lines: config.live.as_ref().map(|l| l.lines).unwrap_or(10),
    };

    for entry in &config.filters {
        let direction = entry.direction.as_deref().unwrap_or("any");
        let group = match direction {
            "src" => &mut fc.src_only,
            "dst" => &mut fc.dst_only,
            "any" => &mut fc.any,
            other => bail!("unknown direction '{}', expected src/dst/any", other),
        };
        group
            .add(&entry.cidr)
            .with_context(|| format!("invalid filter cidr '{}'", entry.cidr))?;
    }

    Ok(fc)
}

fn build_port_set(config: Option<&HighlightedPortsConfig>) -> HashSet<u16> {
    match config {
        None => DEFAULT_HIGHLIGHTED_PORTS.iter().copied().collect(),
        Some(hp) if hp.mode == "override" => hp.ports.iter().copied().collect(),
        Some(hp) => {
            let mut set: HashSet<u16> = DEFAULT_HIGHLIGHTED_PORTS.iter().copied().collect();
            set.extend(hp.ports.iter().copied());
            set
        }
    }
}
