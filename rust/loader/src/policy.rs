//! Single-machine binding, deny, privileged-port, and quota policy.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::desired::{DesiredPorts, PortBinding};
use crate::ports::parse_port_list_flexible;

const DEFAULT_DENY: &[u16] = &[22, 25, 53, 3306, 6379];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub deny: BTreeSet<u16>,
    pub allow_privileged: BTreeSet<u16>,
    pub max_ports_per_tenant: usize,
    pub max_ports_per_machine: usize,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            deny: DEFAULT_DENY.iter().copied().collect(),
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
    let text =
        fs::read_to_string(path).with_context(|| format!("read policy file {}", path.display()))?;
    parse(&text).with_context(|| format!("parse policy file {}", path.display()))
}

fn parse(raw: &str) -> Result<Policy> {
    let mut out = Policy::default();
    let mut allow_seen = false;
    #[allow(clippy::needless_range_loop)]
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
                out.deny.extend(
                    parse_port_list_flexible(value.trim())
                        .with_context(|| format!("line {line_no}: deny"))?,
                );
            }
            "allow_privileged" => {
                if !allow_seen {
                    out.allow_privileged.clear();
                    allow_seen = true;
                }
                if !value.trim().is_empty() {
                    out.allow_privileged.extend(
                        parse_port_list_flexible(value.trim())
                            .with_context(|| format!("line {line_no}: allow_privileged"))?,
                    );
                }
            }
            "max_ports_per_tenant" => {
                out.max_ports_per_tenant = value
                    .trim()
                    .parse()
                    .with_context(|| format!("line {line_no}: max_ports_per_tenant"))?
            }
            "max_ports_per_machine" => {
                out.max_ports_per_machine = value
                    .trim()
                    .parse()
                    .with_context(|| format!("line {line_no}: max_ports_per_machine"))?
            }
            other => bail!("line {line_no}: unknown policy key {other:?}"),
        }
    }
    // Fail at parse time rather than at the first map write that overflows.
    validate_capacity(&out)?;
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
    if let Some(cert) = &binding.cert {
        valid_identity("cert", cert)?;
    }
    if let Some(id) = &binding.policy {
        valid_identity("policy", id)?;
    }
    if policy.deny.contains(&port) {
        bail!("port {port} is denied by policy");
    }
    if port <= 1023 && !policy.allow_privileged.contains(&port) {
        bail!("privileged port {port} is not in allow_privileged");
    }
    Ok(())
}

pub fn validate(desired: &DesiredPorts, policy: &Policy) -> Result<()> {
    if desired.len() > policy.max_ports_per_machine {
        bail!(
            "machine port quota exceeded: {} > {}",
            desired.len(),
            policy.max_ports_per_machine
        );
    }
    let mut tenants: HashMap<&str, usize> = HashMap::new();
    for (key, binding) in desired {
        validate_binding(key.port, binding, policy)?;
        let n = tenants.entry(binding.tenant.as_str()).or_default();
        *n += 1;
        if *n > policy.max_ports_per_tenant {
            bail!(
                "tenant {:?} port quota exceeded: {} > {}",
                binding.tenant,
                n,
                policy.max_ports_per_tenant
            );
        }
    }
    Ok(())
}

/// Reject a policy whose machine quota exceeds what the dataplane can hold.
///
/// Without this, a policy edit can promise more ports than `open_ports` has
/// room for and the overflow only surfaces as `E2BIG` on the map write of
/// whichever tenant happens to be applied last — an arbitrary victim, far from
/// the change that caused it.
pub fn validate_capacity(policy: &Policy) -> Result<()> {
    let capacity = crate::pin::OPEN_PORTS_MAX_ENTRIES as usize;
    if policy.max_ports_per_machine > capacity {
        bail!(
            "max_ports_per_machine={} exceeds open_ports capacity {capacity}; \
             raise open_ports max_entries in dispatch.bpf.c (and pin.rs) first",
            policy.max_ports_per_machine
        );
    }
    if policy.max_ports_per_tenant > policy.max_ports_per_machine {
        bail!(
            "max_ports_per_tenant={} exceeds max_ports_per_machine={}: a single \
             tenant could exhaust the machine quota",
            policy.max_ports_per_tenant,
            policy.max_ports_per_machine
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::desired::PortBinding;
    use crate::pin::REDIR_PRIMARY;

    use crate::key::PortKey;

    fn binding(tenant: &str) -> PortBinding {
        PortBinding::new(REDIR_PRIMARY as u8, tenant, "www")
    }

    #[test]
    fn defaults_deny_named_and_privileged_ports() {
        let p = Policy::default();
        for port in DEFAULT_DENY {
            assert!(validate_binding(*port, &binding("acme"), &p).is_err());
        }
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
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("policy.conf");
        let policy = load(&path).unwrap();
        assert!(!policy.allow_privileged.contains(&80));
        assert!(!policy.allow_privileged.contains(&443));
        assert!(validate_binding(80, &binding("acme"), &policy).is_err());
    }

    #[test]
    fn tenant_quota_accepts_32_rejects_33() {
        let p = Policy::default();
        let mut d = DesiredPorts::new();
        for port in 10_000..10_032 {
            d.insert(PortKey::wildcard_v4(port), binding("acme"));
        }
        assert!(validate(&d, &p).is_ok());
        d.insert(PortKey::wildcard_v4(10_032), binding("acme"));
        assert!(validate(&d, &p).unwrap_err().to_string().contains("tenant"));
    }

    #[test]
    fn machine_quota_rejects_129_across_tenants() {
        let mut p = Policy::default();
        p.max_ports_per_tenant = 128;
        let mut d = DesiredPorts::new();
        for i in 0..129u16 {
            d.insert(PortKey::wildcard_v4(20_000 + i), binding(&format!("t{i}")));
        }
        assert!(validate(&d, &p)
            .unwrap_err()
            .to_string()
            .contains("machine"));
    }

    #[test]
    fn quota_beyond_map_capacity_is_refused_at_parse_time() {
        // The failure must name the dataplane limit, not surface later as an
        // E2BIG on an unrelated tenant's map write.
        let too_big = crate::pin::OPEN_PORTS_MAX_ENTRIES as usize + 1;
        let err = parse(&format!(
            "max_ports_per_machine = {too_big}\nmax_ports_per_tenant = 1\n"
        ))
        .unwrap_err()
        .to_string();
        assert!(err.contains("open_ports capacity"), "{err}");
    }

    #[test]
    fn tenant_quota_above_machine_quota_is_refused() {
        let err = parse("max_ports_per_machine = 10\nmax_ports_per_tenant = 11\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("exceeds max_ports_per_machine"), "{err}");
    }

    #[test]
    fn default_policy_fits_the_dataplane() {
        validate_capacity(&Policy::default()).unwrap();
    }
}
