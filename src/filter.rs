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
    /// Every address this group accepts, enumerated.
    fn enumerate_into(&self, out: &mut HashSet<u32>, budget: &mut u64) -> anyhow::Result<()> {
        out.extend(self.exact.iter().copied());
        for &(network, mask) in &self.cidrs {
            let count = (!mask as u64) + 1;
            *budget = budget.saturating_sub(count);
            if *budget == 0 {
                bail!(
                    "the filter expands to more than {} addresses; \
                     check that no prefix is wider than intended",
                    EXPAND_LIMIT
                );
            }
            for offset in 0..count {
                out.insert(network.wrapping_add(offset as u32));
            }
        }
        Ok(())
    }

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

    /// Every address the filter can match, enumerated.
    ///
    /// Only `--recompute-5m` needs this: it hands the list to PostgreSQL as a
    /// temporary table so the join is an equality join.  Testing `srcaddr <<= cidr`
    /// against a few thousand single addresses is a nested loop instead — 76
    /// seconds for an hour of raw data against 74 ms.
    ///
    /// Matching at run time still goes through `check`; this is the same set
    /// expressed differently, not a second definition.
    pub fn expand(&self) -> anyhow::Result<HashSet<u32>> {
        let mut out = HashSet::new();
        let mut budget = EXPAND_LIMIT;
        for group in [&self.src_only, &self.dst_only, &self.any] {
            group.enumerate_into(&mut out, &mut budget)?;
        }
        Ok(out)
    }
}

/// Above this, an expansion is a prefix typo rather than an intent, and the
/// temporary table it would build is no longer something to hand PostgreSQL.
const EXPAND_LIMIT: u64 = 1_048_576;

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

#[cfg(test)]
mod tests {
    use super::*;

    fn build_from(entries: &[(&str, &str)]) -> FilterConfig {
        let toml = entries
            .iter()
            .map(|(cidr, dir)| format!("[[filters]]\ncidr = \"{}\"\ndirection = \"{}\"\n", cidr, dir))
            .collect::<String>();
        build(&toml::from_str(&toml).unwrap()).unwrap()
    }

    #[test]
    fn a_range_expands_inclusive_of_network_and_broadcast() {
        let fc = build_from(&[("10.10.1.0/24", "any")]);
        let set = fc.expand().unwrap();
        assert_eq!(set.len(), 256);
        assert!(set.contains(&u32::from(Ipv4Addr::new(10, 10, 1, 0))));
        assert!(set.contains(&u32::from(Ipv4Addr::new(10, 10, 1, 255))));
        assert!(!set.contains(&u32::from(Ipv4Addr::new(10, 10, 2, 0))));
    }

    #[test]
    fn overlapping_entries_are_deduplicated() {
        let fc = build_from(&[("10.10.1.0/24", "any"), ("10.10.1.50", "any"), ("10.10.1.0/25", "any")]);
        assert_eq!(fc.expand().unwrap().len(), 256);
    }

    /// The property the recompute depends on.
    ///
    /// Run time matches with `check`; the recompute hands PostgreSQL the set from
    /// `expand`.  If the two ever disagreed, a rebuild would silently produce
    /// different statistics than the live path did — so assert they are the same
    /// set, over addresses both inside and outside every configured range.
    #[test]
    fn expand_accepts_exactly_what_check_accepts() {
        let fc = build_from(&[
            ("10.10.1.0/24", "any"),
            ("10.10.5.7", "any"),
            ("192.168.0.0/30", "any"),
        ]);
        let expanded = fc.expand().unwrap();

        // Sweep a range that straddles all three entries plus their neighbours.
        for base in [
            u32::from(Ipv4Addr::new(10, 10, 0, 250)),
            u32::from(Ipv4Addr::new(10, 10, 5, 0)),
            u32::from(Ipv4Addr::new(192, 167, 255, 250)),
        ] {
            for ip in base..base + 600 {
                let matched = fc.check(ip, 0).src_matched;
                assert_eq!(
                    matched,
                    expanded.contains(&ip),
                    "check and expand disagree on {}",
                    Ipv4Addr::from(ip)
                );
            }
        }
    }

    #[test]
    fn direction_decides_which_side_is_counted() {
        let fc = build_from(&[("10.10.1.50", "src")]);
        let host = u32::from(Ipv4Addr::new(10, 10, 1, 50));
        let other = u32::from(Ipv4Addr::new(8, 8, 8, 8));

        // Sending: counted (tx).  Receiving: not matched at all.
        assert!(fc.check(host, other).src_matched);
        assert!(!fc.check(other, host).dst_matched);
    }

    #[test]
    fn an_absurd_prefix_is_refused_rather_than_exhausting_memory() {
        let fc = build_from(&[("10.0.0.0/8", "any")]);
        assert!(fc.expand().unwrap_err().to_string().contains("more than"));
    }
}
