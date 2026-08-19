//! Single-machine binding, deny, privileged-port, and quota policy.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::desired::{DesiredPorts, PortBinding};
use crate::key::{Dest, PortKey};
use crate::ports::parse_port_list_flexible;

const DEFAULT_DENY: &[u16] = &[22, 25, 53, 3306, 6379];

/// A family/address-aware endpoint that a dynamic binding must not capture.
/// `source` is intentionally bounded (policy.conf or a loader-owned runtime
/// endpoint name) so it is safe to surface in audit/status output.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReservedEndpoint {
    pub port: u16,
    pub dest: Dest,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub deny: BTreeSet<u16>,
    /// Management/fixed-listener ports that dynamic WAF bindings may never
    /// claim. Unlike `deny`, this is an operational isolation rule and its
    /// error tells operators to move/declare the endpoint or use an exact VIP.
    pub reserve: BTreeSet<u16>,
    /// `reserve_endpoint=` entries preserve multi-VIP isolation unlike legacy
    /// `reserve=`, which intentionally remains a conservative global-port rule.
    pub reserve_endpoints: BTreeSet<ReservedEndpoint>,
    pub allow_privileged: BTreeSet<u16>,
    pub max_ports_per_tenant: usize,
    pub max_ports_per_machine: usize,
    /// Optional pressure threshold (1..=99) at which new mutations are
    /// rejected before the pinned map is exhausted. `None` preserves legacy
    /// quota-only behavior for existing policies.
    pub pressure_freeze_pct: Option<u8>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            deny: DEFAULT_DENY.iter().copied().collect(),
            reserve: BTreeSet::new(),
            reserve_endpoints: BTreeSet::new(),
            allow_privileged: BTreeSet::new(),
            max_ports_per_tenant: 32,
            max_ports_per_machine: 128,
            pressure_freeze_pct: None,
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
            "reserve" => {
                out.reserve.extend(
                    parse_port_list_flexible(value.trim())
                        .with_context(|| format!("line {line_no}: reserve"))?,
                );
            }
            "reserve_endpoint" => {
                for endpoint in parse_reserved_endpoints(value.trim())
                    .with_context(|| format!("line {line_no}: reserve_endpoint"))?
                {
                    out.reserve_endpoints.insert(endpoint);
                }
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
            "pressure_freeze_pct" => {
                let pct: u8 = value
                    .trim()
                    .parse()
                    .with_context(|| format!("line {line_no}: pressure_freeze_pct"))?;
                if !(1..=99).contains(&pct) {
                    bail!("line {line_no}: pressure_freeze_pct must be in 1..=99");
                }
                out.pressure_freeze_pct = Some(pct);
            }
            other => bail!("line {line_no}: unknown policy key {other:?}"),
        }
    }
    // Fail at parse time rather than at the first map write that overflows.
    validate_capacity(&out)?;
    Ok(out)
}

fn parse_reserved_endpoints(raw: &str) -> Result<Vec<ReservedEndpoint>> {
    if raw.trim().is_empty() {
        bail!("reserve_endpoint requires IP:PORT or [IPv6]:PORT");
    }
    raw.split(',')
        .map(str::trim)
        .map(|item| {
            let socket: SocketAddr = item.parse().with_context(|| {
                format!("invalid endpoint {item:?}; expected IP:PORT or [IPv6]:PORT")
            })?;
            if socket.port() == 0 {
                bail!("endpoint {item:?} has invalid port 0");
            }
            let dest = match socket.ip() {
                IpAddr::V4(ip) if ip.is_unspecified() => Dest::AnyV4,
                IpAddr::V4(ip) => Dest::V4(ip),
                IpAddr::V6(ip) if ip.is_unspecified() => Dest::AnyV6,
                IpAddr::V6(ip) => Dest::V6(ip),
            };
            Ok(ReservedEndpoint {
                port: socket.port(),
                dest,
                source: "policy.conf".into(),
            })
        })
        .collect()
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
    if policy.reserve.contains(&port) {
        bail!(
            "port {port} is reserved by policy (management/fixed listener); \
             use a distinct ingress VIP or update the reservation policy"
        );
    }
    if port <= 1023 && !policy.allow_privileged.contains(&port) {
        bail!("privileged port {port} is not in allow_privileged");
    }
    Ok(())
}

fn endpoints_intersect(binding: Dest, reserved: Dest) -> bool {
    if binding.family() != reserved.family() {
        return false;
    }
    binding.is_wildcard() || reserved.is_wildcard() || binding == reserved
}

fn validate_endpoint_reservations(key: PortKey, policy: &Policy) -> Result<()> {
    for reservation in &policy.reserve_endpoints {
        if key.port == reservation.port && endpoints_intersect(key.dest, reservation.dest) {
            bail!(
                "binding {key} conflicts with reserved endpoint {}:{} ({}) ; use a distinct ingress VIP or change the management endpoint",
                reservation.dest,
                reservation.port,
                reservation.source
            );
        }
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
        validate_endpoint_reservations(*key, policy)?;
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
/// Verify a projected number of `open_ports` entries against the optional
/// pressure admission threshold. The threshold is intentionally exclusive: at
/// `pct%` the controller stops accepting new state so operators retain
/// headroom for recovery/rollback rather than racing the hard map limit.
pub fn validate_pressure_entries(entries: usize, policy: &Policy) -> Result<()> {
    let Some(pct) = policy.pressure_freeze_pct else {
        return Ok(());
    };
    let capacity = crate::pin::OPEN_PORTS_MAX_ENTRIES as usize;
    // Compare the ratio before rounding. For 131072 * 80%, 104857 entries is
    // still below 80%; only 104858 reaches/exceeds it. A floored threshold
    // would reject one valid entry early and make the policy boundary opaque.
    let threshold_at_or_above = (capacity * pct as usize).div_ceil(100);
    if entries.saturating_mul(100) >= capacity * pct as usize {
        bail!(
            "pressure freeze threshold reached: projected_entries={entries} threshold_at_or_above={threshold_at_or_above} capacity={capacity} pct={pct}; refuse new mutation before map exhaustion"
        );
    }
    Ok(())
}

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
    if let Some(pct) = policy.pressure_freeze_pct {
        if !(1..=99).contains(&pct) {
            bail!("pressure_freeze_pct must be in 1..=99");
        }
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

    // SDD-003 / T-041: admission must reject before map exhaustion, with a
    // policy-defined pressure threshold rather than an implicit E2BIG later.
    #[test]
    fn pressure_freeze_threshold_parses_and_rejects_projected_occupancy() {
        let p = parse(
            "max_ports_per_machine=131072\nmax_ports_per_tenant=131072\npressure_freeze_pct=80\n",
        )
        .unwrap();
        assert_eq!(p.pressure_freeze_pct, Some(80));
        assert!(validate_pressure_entries(104_857, &p).is_ok());
        let err = validate_pressure_entries(104_858, &p)
            .unwrap_err()
            .to_string();
        assert!(err.contains("pressure freeze threshold"), "{err}");
        let err = parse("pressure_freeze_pct=100\n").unwrap_err().to_string();
        assert!(err.contains("1..=99"), "{err}");
    }

    #[test]
    fn default_policy_fits_the_dataplane() {
        validate_capacity(&Policy::default()).unwrap();
    }

    // SDD-001 / T-001: management-port reservations are a policy primitive,
    // not an operator convention. Multiple lines compose so layered policy
    // files can reserve exporter, ctl, and host-agent ports independently.
    #[test]
    fn reserve_lines_merge_and_reject_before_mutation() {
        let p = parse("reserve=9101,17171\nreserve=19104\n").unwrap();
        assert!(p.reserve.contains(&9101));
        assert!(p.reserve.contains(&17171));
        assert!(p.reserve.contains(&19104));
        let err = validate_binding(19104, &binding("acme"), &p)
            .unwrap_err()
            .to_string();
        assert!(err.contains("reserved"), "{err}");
    }

    // SDD-001 / T-001: deny and reserve remain distinct operator messages.
    // A reserved metrics/ctl port is not a security deny; remediation is to
    // move/declare the management endpoint or use a distinct ingress VIP.
    #[test]
    fn reserve_is_distinct_from_deny() {
        let p = parse("reserve=9101\n").unwrap();
        assert!(validate_binding(9101, &binding("acme"), &p)
            .unwrap_err()
            .to_string()
            .contains("reserved"));
        assert!(validate_binding(22, &binding("acme"), &p)
            .unwrap_err()
            .to_string()
            .contains("denied"));
    }

    // SDD-001 / T-002: the checked-in deployment policy must reserve the
    // default internal and metrics endpoints, so an operator cannot turn the
    // default control plane into a wildcard dynamic-port binding by accident.
    // SDD-002 / T-020..T-022: endpoint reservations are family/address aware.
    // A loopback exporter must not prevent an exact public VIP from claiming
    // the same numeric port, while wildcard IPv4 would capture that exporter.
    #[test]
    fn exact_reservation_preserves_multi_vip_isolation() {
        let p = parse("reserve_endpoint=127.0.0.1:9101\n").unwrap();
        let mut desired = DesiredPorts::new();
        desired.insert(
            PortKey::new(9101, crate::key::Dest::V4("10.0.0.10".parse().unwrap())),
            binding("acme"),
        );
        assert!(validate(&desired, &p).is_ok());

        desired.clear();
        desired.insert(
            PortKey::new(9101, crate::key::Dest::V4("127.0.0.1".parse().unwrap())),
            binding("acme"),
        );
        let same = validate(&desired, &p).unwrap_err().to_string();
        assert!(same.contains("policy.conf"), "{same}");

        desired.clear();
        desired.insert(PortKey::wildcard_v4(9101), binding("acme"));
        assert!(validate(&desired, &p).is_err());

        desired.clear();
        desired.insert(PortKey::new(9101, crate::key::Dest::AnyV6), binding("acme"));
        assert!(validate(&desired, &p).is_ok());
    }

    #[test]
    fn repository_policy_reserves_default_management_endpoints() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("policy.conf");
        let policy = load(&path).unwrap();
        for port in [8080, 8443, 9101] {
            assert!(policy.reserve.contains(&port), "missing reserve={port}");
        }
    }
}
