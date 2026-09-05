//! Single-machine binding, deny, privileged-port, quota, and reserved-port policy.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::desired::{DesiredPorts, PortBinding};
use crate::pin::OPEN_PORTS_MAX_ENTRIES;
use crate::ports::parse_port_list_flexible;

const DEFAULT_DENY: &[u16] = &[22, 25, 53, 3306, 6379];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub deny: BTreeSet<u16>,
    pub reserve: BTreeSet<u16>,
    pub allow_privileged: BTreeSet<u16>,
    pub max_ports_per_tenant: usize,
    pub max_ports_per_machine: usize,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            deny: DEFAULT_DENY.iter().copied().collect(),
            reserve: BTreeSet::new(),
            allow_privileged: BTreeSet::new(),
            max_ports_per_tenant: 32,
            max_ports_per_machine: 128,
        }
    }
}

pub fn default_path(ports_file: &Path) -> PathBuf {
    ports_file
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .join("policy.conf")
}

pub fn load(path: &Path) -> Result<Policy> {
    if !path.exists() {
        return Ok(Policy::default());
    }
    let text = fs::read_to_string(path)
        .with_context(|| format!("read policy file {}", path.display()))?;
    parse(&text).with_context(|| format!("parse policy file {}", path.display()))
}

fn parse(raw: &str) -> Result<Policy> {
    let mut out = Policy::default();
    let mut allow_seen = false;
    for (i, original) in raw.lines().enumerate() {
        let line_no = i + 1;
        let line = original.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("line {line_no}: expected key=value"))?;
        match key.trim() {
            "deny" => {
                out.deny.extend(parse_port_list_flexible(value.trim()).with_context(|| format!("line {line_no}: deny"))?);
            }
            "reserve" => {
                out.reserve.extend(parse_port_list_flexible(value.trim()).with_context(|| format!("line {line_no}: reserve"))?);
            }
            "allow_privileged" => {
                if !allow_seen { out.allow_privileged.clear(); allow_seen = true; }
                if !value.trim().is_empty() {
                    out.allow_privileged.extend(parse_port_list_flexible(value.trim()).with_context(|| format!("line {line_no}: allow_privileged"))?);
                }
            }
            "max_ports_per_tenant" => out.max_ports_per_tenant = value.trim().parse().with_context(|| format!("line {line_no}: max_ports_per_tenant"))?,
            "max_ports_per_machine" => out.max_ports_per_machine = value.trim().parse().with_context(|| format!("line {line_no}: max_ports_per_machine"))?,
            other => bail!("line {line_no}: unknown policy key {other:?}"),
        }
    }
    Ok(out)
}

fn valid_identity(name: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.chars().any(char::is_whitespace) {
        bail!("{name} must be non-empty and contain no whitespace (binding is mandatory; see docs/binding.md)");
    }
    Ok(())
}

pub fn validate_binding(port: u16, binding: &PortBinding, policy: &Policy) -> Result<()> {
    valid_identity("tenant", &binding.tenant)?;
    valid_identity("site", &binding.site)?;
    if let Some(cert) = &binding.cert { valid_identity("cert", cert)?; }
    if let Some(id) = &binding.policy { valid_identity("policy", id)?; }
    if policy.deny.contains(&port) {
        bail!("port {port} is denied by policy");
    }
    if policy.reserve.contains(&port) {
        bail!(
            "port {port} is reserved (management/fixed listener); use a different ingress port or update reserve= in policy.conf"
        );
    }
    if port <= 1023 && !policy.allow_privileged.contains(&port) {
        bail!("privileged port {port} is not in allow_privileged");
    }
    Ok(())
}

/// Merge a listen address's port into the reserved set (runtime injection).
pub fn reserve_listen_target(policy: &mut Policy, addr: &str) {
    if let Some(port) = port_of_listen_addr(addr) {
        policy.reserve.insert(port);
    }
}

pub fn port_of_listen_addr(addr: &str) -> Option<u16> {
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        return Some(sa.port());
    }
    addr.rsplit_once(':')
        .and_then(|(_, p)| p.trim_end_matches(']').parse().ok())
}

pub fn validate(desired: &DesiredPorts, policy: &Policy) -> Result<()> {
    if desired.len() > OPEN_PORTS_MAX_ENTRIES as usize {
        bail!(
            "open_ports capacity exceeded: {} > {OPEN_PORTS_MAX_ENTRIES}",
            desired.len()
        );
    }
    if desired.len() > policy.max_ports_per_machine {
        bail!("machine port quota exceeded: {} > {}", desired.len(), policy.max_ports_per_machine);
    }
    let mut tenants: HashMap<&str, usize> = HashMap::new();
    for (port, binding) in desired {
        validate_binding(*port, binding, policy)?;
        let n = tenants.entry(binding.tenant.as_str()).or_default();
        *n += 1;
        if *n > policy.max_ports_per_tenant {
            bail!("tenant {:?} port quota exceeded: {} > {}", binding.tenant, n, policy.max_ports_per_tenant);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::desired::PortBinding;
    use crate::pin::REDIR_PRIMARY;

    fn binding(tenant: &str) -> PortBinding {
        PortBinding { slot: REDIR_PRIMARY as u8, tenant: tenant.into(), site: "www".into(), cert: None, policy: None }
    }

    #[test]
    fn defaults_deny_named_and_privileged_ports() {
        let p = Policy::default();
        for port in DEFAULT_DENY { assert!(validate_binding(*port, &binding("acme"), &p).is_err()); }
        assert!(validate_binding(80, &binding("acme"), &p).is_err());
    }

    #[test]
    fn privileged_allowlist_works() {
        let mut p = Policy::default();
        p.allow_privileged.insert(80);
        assert!(validate_binding(80, &binding("acme"), &p).is_ok());
    }

    #[test]
    fn repository_policy_does_not_allow_real_listen_ports() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join("policy.conf");
        let policy = load(&path).unwrap();
        assert!(!policy.allow_privileged.contains(&80));
        assert!(!policy.allow_privileged.contains(&443));
        assert!(validate_binding(80, &binding("acme"), &policy).is_err());
    }

    #[test]
    fn tenant_quota_accepts_32_rejects_33() {
        let p = Policy::default();
        let mut d = DesiredPorts::new();
        for port in 10_000..10_032 { d.insert(port, binding("acme")); }
        assert!(validate(&d, &p).is_ok());
        d.insert(10_032, binding("acme"));
        assert!(validate(&d, &p).unwrap_err().to_string().contains("tenant"));
    }

    #[test]
    fn machine_quota_rejects_129_across_tenants() {
        let mut p = Policy::default();
        p.max_ports_per_tenant = 128;
        let mut d = DesiredPorts::new();
        for i in 0..129u16 { d.insert(20_000 + i, binding(&format!("t{i}"))); }
        assert!(validate(&d, &p).unwrap_err().to_string().contains("machine"));
    }

    #[test]
    fn reserve_lines_merge_and_reject_binding() {
        let p = parse("reserve=8080,8443\nreserve=9101\n").unwrap();
        assert_eq!(p.reserve, [8080, 8443, 9101].into_iter().collect());
        assert!(validate_binding(8080, &binding("acme"), &p)
            .unwrap_err()
            .to_string()
            .contains("reserved"));
        assert!(validate_binding(18081, &binding("acme"), &p).is_ok());
    }

    #[test]
    fn missing_reserve_keeps_compat_defaults() {
        let p = Policy::default();
        assert!(p.reserve.is_empty());
        assert!(validate_binding(18081, &binding("acme"), &p).is_ok());
        assert!(validate_binding(8080, &binding("acme"), &p).is_ok());
    }

    #[test]
    fn repository_policy_reserves_inner_listens() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join("policy.conf");
        let policy = load(&path).unwrap();
        for port in [80, 443, 8080, 8443] {
            assert!(policy.reserve.contains(&port), "missing reserve {port}");
            assert!(validate_binding(port, &binding("acme"), &policy).is_err());
        }
    }

    #[test]
    fn runtime_target_is_merged_into_reserve() {
        let mut p = Policy::default();
        reserve_listen_target(&mut p, "127.0.0.1:8080");
        reserve_listen_target(&mut p, "127.0.0.1:8443");
        assert_eq!(p.reserve, [8080, 8443].into_iter().collect());
        assert_eq!(port_of_listen_addr("127.0.0.1:18080"), Some(18080));
    }

    #[test]
    fn invalid_reserve_port_is_parse_error() {
        assert!(parse("reserve=notaport\n").is_err());
    }
}
