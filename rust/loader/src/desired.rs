//! File-backed desired state for `open_ports`.

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use anyhow::{bail, Context, Result};
use libbpf_rs::{MapCore, MapFlags};
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use crate::key::{Dest, PortKey, PortVal};
use crate::pin::{OPEN_PORTS_MAX_ENTRIES, REDIR_PRIMARY, REDIR_TLS};
use crate::ports::parse_port_list_flexible;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortBinding {
    /// Protocol group inside `redir_socket` (0 = primary, 1 = stock TLS).
    pub slot: u8,
    pub tenant: String,
    pub site: String,
    pub cert: Option<String>,
    pub policy: Option<String>,
    /// Destination address this port is steered on. Defaults to the IPv4
    /// wildcard so existing single-VIP `ports.conf` files behave as before.
    pub dest: Dest,
}

impl PortBinding {
    /// Binding used by tests and by `from_lists`.
    pub fn new(slot: u8, tenant: &str, site: &str) -> Self {
        Self {
            slot,
            tenant: tenant.into(),
            site: site.into(),
            cert: None,
            policy: None,
            dest: Dest::AnyV4,
        }
    }
}

/// Desired state is keyed by (family, address, port), not by port alone: a
/// multi-VIP host must be able to steer the same port on one VIP without
/// hijacking it on every other address.
pub type DesiredPorts = BTreeMap<PortKey, PortBinding>;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReconcilePlan {
    pub put_primary: Vec<PortKey>,
    pub put_tls: Vec<PortKey>,
    pub delete: Vec<PortKey>,
}

impl ReconcilePlan {
    pub fn is_empty(&self) -> bool {
        self.put_primary.is_empty() && self.put_tls.is_empty() && self.delete.is_empty()
    }

    pub fn put_len(&self) -> usize {
        self.put_primary.len() + self.put_tls.len()
    }
}

#[allow(dead_code)]
pub fn load(path: &Path) -> Result<DesiredPorts> {
    load_with_policy(path, &crate::policy::default_path(path))
}

pub fn load_with_policy(path: &Path, policy_path: &Path) -> Result<DesiredPorts> {
    let file =
        File::open(path).with_context(|| format!("open desired ports file {}", path.display()))?;
    let policy = crate::policy::load(policy_path)?;
    load_from_reader_with_policy(file, &policy)
        .with_context(|| format!("read desired ports file {}", path.display()))
}

pub fn load_from_reader(reader: impl std::io::Read) -> Result<DesiredPorts> {
    load_from_reader_with_policy(reader, &crate::policy::Policy::default())
}

pub fn load_from_reader_with_policy(
    reader: impl std::io::Read,
    policy: &crate::policy::Policy,
) -> Result<DesiredPorts> {
    let mut desired = DesiredPorts::new();
    for (i, line) in BufReader::new(reader).lines().enumerate() {
        let line_no = i + 1;
        let mut line = line.with_context(|| format!("line {line_no}"))?;
        if let Some(i) = line.find('#') {
            line.truncate(i);
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 3 {
            bail!("line {line_no}: port-only desired state is no longer accepted; tenant and site binding is mandatory (see docs/binding.md)");
        }
        let spec = fields[0];
        let tenant = fields[1].to_string();
        let site = fields[2].to_string();
        let mut slot = REDIR_PRIMARY as u8;
        let mut cert = None;
        let mut policy_id = None;
        let mut dest = None;
        for token in &fields[3..] {
            match *token {
                "tls" if slot == REDIR_PRIMARY as u8 => slot = REDIR_TLS as u8,
                t if t.starts_with("cert=") && cert.is_none() => cert = Some(t[5..].to_string()),
                t if t.starts_with("policy=") && policy_id.is_none() => {
                    policy_id = Some(t[7..].to_string())
                }
                t if t.starts_with("addr=") && dest.is_none() => {
                    dest = Some(Dest::parse(&t[5..]).with_context(|| format!("line {line_no}"))?)
                }
                other => bail!("line {line_no}: unexpected or duplicate token {other:?}"),
            }
        }
        // No addr= token means the IPv4 wildcard, i.e. exactly the old
        // port-only behaviour, so existing files keep working unchanged.
        let binding = PortBinding {
            slot,
            tenant,
            site,
            cert,
            policy: policy_id,
            dest: dest.unwrap_or(Dest::AnyV4),
        };
        for port in parse_port_list_flexible(spec).with_context(|| format!("line {line_no}"))? {
            crate::policy::validate_binding(port, &binding, policy)
                .with_context(|| format!("line {line_no}"))?;
            let key = PortKey::new(port, binding.dest);
            if let Some(old) = desired.insert(key, binding.clone()) {
                if old != binding {
                    bail!("line {line_no}: {key} has conflicting bindings");
                }
            }
        }
    }
    if desired.len() > OPEN_PORTS_MAX_ENTRIES as usize {
        bail!(
            "desired file has {} ports; open_ports max_entries is {OPEN_PORTS_MAX_ENTRIES}",
            desired.len()
        );
    }
    crate::policy::validate(&desired, policy)?;
    Ok(desired)
}

pub fn write(path: &Path, desired: &DesiredPorts) -> Result<()> {
    let old_metadata = fs::metadata(path).ok();
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("ports.conf");
    let tmp = parent.join(format!(".{name}.tmp.{}", std::process::id()));
    let result = (|| -> Result<()> {
        let mut file = File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
        #[cfg(unix)]
        if let Some(metadata) = &old_metadata {
            file.set_permissions(fs::Permissions::from_mode(metadata.mode()))?;
            if unsafe { libc::geteuid() } == 0 {
                let rc = unsafe { libc::fchown(file.as_raw_fd(), metadata.uid(), metadata.gid()) };
                if rc != 0 {
                    return Err(std::io::Error::last_os_error())
                        .context("preserve desired file owner");
                }
            }
        }
        writeln!(file, "# desired open_ports")?;
        writeln!(
            file,
            "# PORT TENANT SITE [tls] [cert=ID] [policy=ID] [addr=IP|*]"
        )?;
        for (key, b) in desired {
            write!(file, "{} {} {}", key.port, b.tenant, b.site)?;
            if b.slot == REDIR_TLS as u8 {
                write!(file, " tls")?;
            }
            if let Some(cert) = &b.cert {
                write!(file, " cert={cert}")?;
            }
            if let Some(policy) = &b.policy {
                write!(file, " policy={policy}")?;
            }
            // Only emit addr= when it is not the implicit IPv4 wildcard, so
            // round-tripping a legacy file does not rewrite every line.
            if b.dest != Dest::AnyV4 {
                write!(file, " addr={}", b.dest)?;
            }
            writeln!(file)?;
        }
        file.sync_all()?;
        fs::rename(&tmp, path).with_context(|| format!("replace {}", path.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

pub fn from_lists(primary: &[u16], tls: &[u16], tenant: &str, site: &str) -> Result<DesiredPorts> {
    let mut desired = DesiredPorts::new();
    for (ports, slot) in [(primary, REDIR_PRIMARY as u8), (tls, REDIR_TLS as u8)] {
        for p in ports {
            let b = PortBinding::new(slot, tenant, site);
            if desired.insert(PortKey::wildcard_v4(*p), b).is_some() {
                bail!("port {p} is assigned to both primary and tls");
            }
        }
    }
    Ok(desired)
}

/// Live `open_ports` contents: key -> (group, shards).
pub type CurrentPorts = HashMap<PortKey, PortVal>;

pub fn plan(desired: &DesiredPorts, current: &CurrentPorts) -> ReconcilePlan {
    let mut plan = ReconcilePlan::default();
    for (key, binding) in desired {
        // A shard-count change alone is not a reconcile trigger: shard counts
        // follow the live listen set and are refreshed by `retarget_shards`.
        if current.get(key).map(|v| v.group) != Some(binding.slot) {
            if binding.slot == REDIR_TLS as u8 {
                plan.put_tls.push(*key);
            } else {
                plan.put_primary.push(*key);
            }
        }
    }
    for key in current.keys() {
        if !desired.contains_key(key) {
            plan.delete.push(*key);
        }
    }
    plan.put_primary.sort_unstable();
    plan.put_tls.sort_unstable();
    plan.delete.sort_unstable();
    plan
}

pub fn read_map(map: &(impl MapCore + ?Sized)) -> Result<CurrentPorts> {
    let mut current = CurrentPorts::new();
    for raw_key in map.keys() {
        // Skip keys we cannot decode rather than mis-attributing them: a
        // foreign layout means the dataplane is not ours to interpret.
        let Ok(key) = PortKey::from_bytes(&raw_key) else {
            continue;
        };
        let value = map.lookup(&raw_key, MapFlags::ANY)?.unwrap_or_default();
        current.insert(key, PortVal::from_bytes(&value));
    }
    Ok(current)
}

/// Apply a plan to the live map. `shards` is the number of populated worker
/// slots in each protocol group, which the BPF program uses to pick a shard.
pub fn reconcile_map_with_shards(
    map: &(impl MapCore + ?Sized),
    desired: &DesiredPorts,
    shards: u8,
) -> Result<ReconcilePlan> {
    let plan = plan(desired, &read_map(map)?);
    for (keys, group) in [
        (&plan.put_primary, REDIR_PRIMARY as u8),
        (&plan.put_tls, REDIR_TLS as u8),
    ] {
        for key in keys {
            map.update(
                &key.to_bytes(),
                &PortVal::new(group, shards).to_bytes(),
                MapFlags::ANY,
            )
            .with_context(|| format!("open_ports put {key}"))?;
        }
    }
    for key in &plan.delete {
        map.delete(&key.to_bytes())
            .with_context(|| format!("open_ports delete {key}"))?;
    }
    Ok(plan)
}

pub fn reconcile_map(
    map: &(impl MapCore + ?Sized),
    desired: &DesiredPorts,
) -> Result<ReconcilePlan> {
    reconcile_map_with_shards(map, desired, 1)
}

/// Rewrite the shard count of every live entry. Called after the listen set
/// changes (worker start/stop) so the dataplane never selects a shard index
/// beyond the populated range.
pub fn retarget_shards(map: &(impl MapCore + ?Sized), shards: u8) -> Result<usize> {
    let shards = shards.max(1);
    let mut updated = 0usize;
    for (key, val) in read_map(map)? {
        if val.shards == shards {
            continue;
        }
        map.update(
            &key.to_bytes(),
            &PortVal::new(val.group, shards).to_bytes(),
            MapFlags::ANY,
        )
        .with_context(|| format!("open_ports retarget {key}"))?;
        updated += 1;
    }
    Ok(updated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn v4(port: u16) -> PortKey {
        PortKey::wildcard_v4(port)
    }

    #[test]
    fn parses_comments_ranges_commas_and_tls() {
        let got=load_from_reader(Cursor::new("# desired\n18081,18082 acme www\n20000-20001 acme api\n18443 acme www tls cert=www policy=default # fallback\n")).unwrap();
        assert_eq!(got.get(&v4(18081)).unwrap().slot, REDIR_PRIMARY as u8);
        assert_eq!(got.get(&v4(20001)).unwrap().site, "api");
        assert_eq!(got.get(&v4(18443)).unwrap().slot, REDIR_TLS as u8);
    }

    #[test]
    fn old_format_and_missing_binding_are_rejected() {
        for line in ["18081\n", "18443 tls\n", "18081 acme\n"] {
            let e = load_from_reader(Cursor::new(line)).unwrap_err().to_string();
            assert!(e.contains("binding") && e.contains("docs/binding.md"));
        }
    }

    #[test]
    fn plans_missing_wrong_group_and_extra() {
        let desired = from_lists(&[10010, 10011], &[10012], "acme", "www").unwrap();
        let current = CurrentPorts::from([
            (v4(10010), PortVal::new(REDIR_PRIMARY as u8, 1)),
            (v4(10012), PortVal::new(REDIR_PRIMARY as u8, 1)),
            (v4(10013), PortVal::new(REDIR_PRIMARY as u8, 1)),
        ]);
        assert_eq!(
            plan(&desired, &current),
            ReconcilePlan {
                put_primary: vec![v4(10011)],
                put_tls: vec![v4(10012)],
                delete: vec![v4(10013)],
            }
        );
    }

    #[test]
    fn shard_count_change_alone_is_not_a_reconcile() {
        // Shard counts track the live listen set, not the desired file, so a
        // differing shard count must not produce churn in the plan.
        let desired = from_lists(&[10010], &[], "acme", "www").unwrap();
        let current = CurrentPorts::from([(v4(10010), PortVal::new(REDIR_PRIMARY as u8, 8))]);
        assert!(plan(&desired, &current).is_empty());
    }

    #[test]
    fn addr_token_makes_same_port_distinct_per_vip() {
        let got = load_from_reader(Cursor::new(
            "30000 acme www addr=10.0.0.1\n30000 globex www addr=10.0.0.2\n30000 shared www\n",
        ))
        .unwrap();
        assert_eq!(
            got.len(),
            3,
            "same port on different VIPs must not collapse"
        );
        assert_eq!(
            got.get(&PortKey::new(30000, Dest::V4("10.0.0.1".parse().unwrap())))
                .unwrap()
                .tenant,
            "acme"
        );
        assert_eq!(
            got.get(&PortKey::new(30000, Dest::V4("10.0.0.2".parse().unwrap())))
                .unwrap()
                .tenant,
            "globex"
        );
        assert_eq!(got.get(&v4(30000)).unwrap().tenant, "shared");
    }

    #[test]
    fn ipv6_dest_is_parsed_and_distinct_from_v4() {
        let got =
            load_from_reader(Cursor::new("30001 acme www addr=[::]\n30001 acme www\n")).unwrap();
        assert_eq!(got.len(), 2);
        assert!(got.contains_key(&PortKey::new(30001, Dest::AnyV6)));
        assert!(got.contains_key(&v4(30001)));
    }

    #[test]
    fn invalid_addr_is_rejected() {
        let e = format!(
            "{:#}",
            load_from_reader(Cursor::new("30002 acme www addr=nope\n")).unwrap_err()
        );
        assert!(e.contains("invalid destination address"), "{e}");
    }

    #[test]
    fn write_roundtrip_preserves_dest() {
        let dir = std::env::temp_dir().join(format!("waf-desired-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ports.conf");
        let original = load_from_reader(Cursor::new(
            "30000 acme www addr=10.0.0.1\n30001 acme api\n30002 acme tls tls addr=[2001:db8::1]\n",
        ))
        .unwrap();
        write(&path, &original).unwrap();
        let reread = load_from_reader(std::fs::File::open(&path).unwrap()).unwrap();
        assert_eq!(original, reread);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reconcile_refuses_unbound_desired() {
        // load() is the reconcile/apply gate: an unbound file never produces a plan.
        assert!(load_from_reader(Cursor::new("18081\n")).is_err());
        assert!(load_from_reader(Cursor::new("18443 tls\n")).is_err());
        let denied = format!(
            "{:#}",
            load_from_reader(Cursor::new("6379 acme www\n")).unwrap_err()
        );
        assert!(
            denied.contains("denied") || denied.contains("6379"),
            "{denied}"
        );
    }
}
