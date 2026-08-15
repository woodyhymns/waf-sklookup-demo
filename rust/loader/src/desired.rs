//! File-backed desired state for `open_ports`.

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

#[cfg(unix)] use std::os::fd::AsRawFd;
#[cfg(unix)] use std::os::unix::fs::{MetadataExt, PermissionsExt};
use anyhow::{bail, Context, Result};
use libbpf_rs::{MapCore, MapFlags};

use crate::pin::{OPEN_PORTS_MAX_ENTRIES, REDIR_PRIMARY, REDIR_TLS};
use crate::ports::parse_port_list_flexible;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortBinding {
    pub slot: u8,
    pub tenant: String,
    pub site: String,
    pub cert: Option<String>,
    pub policy: Option<String>,
}
pub type DesiredPorts = BTreeMap<u16, PortBinding>;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReconcilePlan { pub put_primary: Vec<u16>, pub put_tls: Vec<u16>, pub delete: Vec<u16> }

#[allow(dead_code)]
pub fn load(path: &Path) -> Result<DesiredPorts> {
    load_with_policy(path, &crate::policy::default_path(path))
}

pub fn load_with_policy(path: &Path, policy_path: &Path) -> Result<DesiredPorts> {
    let file = File::open(path).with_context(|| format!("open desired ports file {}", path.display()))?;
    let policy = crate::policy::load(policy_path)?;
    load_from_reader_with_policy(file, &policy).with_context(|| format!("read desired ports file {}", path.display()))
}

pub fn load_from_reader(reader: impl std::io::Read) -> Result<DesiredPorts> {
    load_from_reader_with_policy(reader, &crate::policy::Policy::default())
}

pub fn load_from_reader_with_policy(reader: impl std::io::Read, policy: &crate::policy::Policy) -> Result<DesiredPorts> {
    let mut desired = DesiredPorts::new();
    for (i, line) in BufReader::new(reader).lines().enumerate() {
        let line_no = i + 1;
        let mut line = line.with_context(|| format!("line {line_no}"))?;
        if let Some(i) = line.find('#') { line.truncate(i); }
        let line = line.trim();
        if line.is_empty() { continue; }
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
        for token in &fields[3..] {
            match *token {
                "tls" if slot == REDIR_PRIMARY as u8 => slot = REDIR_TLS as u8,
                t if t.starts_with("cert=") && cert.is_none() => cert = Some(t[5..].to_string()),
                t if t.starts_with("policy=") && policy_id.is_none() => policy_id = Some(t[7..].to_string()),
                other => bail!("line {line_no}: unexpected or duplicate token {other:?}"),
            }
        }
        let binding = PortBinding { slot, tenant, site, cert, policy: policy_id };
        for port in parse_port_list_flexible(spec).with_context(|| format!("line {line_no}"))? {
            crate::policy::validate_binding(port, &binding, policy).with_context(|| format!("line {line_no}"))?;
            if let Some(old) = desired.insert(port, binding.clone()) {
                if old != binding { bail!("line {line_no}: port {port} has conflicting bindings"); }
            }
        }
    }
    if desired.len() > OPEN_PORTS_MAX_ENTRIES as usize { bail!("desired file has {} ports; open_ports max_entries is {OPEN_PORTS_MAX_ENTRIES}", desired.len()); }
    crate::policy::validate(&desired, policy)?;
    Ok(desired)
}

pub fn write(path: &Path, desired: &DesiredPorts) -> Result<()> {
    let old_metadata = fs::metadata(path).ok();
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("ports.conf");
    let tmp = parent.join(format!(".{name}.tmp.{}", std::process::id()));
    let result = (|| -> Result<()> {
        let mut file = File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
        #[cfg(unix)] if let Some(metadata) = &old_metadata {
            file.set_permissions(fs::Permissions::from_mode(metadata.mode()))?;
            if unsafe { libc::geteuid() } == 0 {
                let rc = unsafe { libc::fchown(file.as_raw_fd(), metadata.uid(), metadata.gid()) };
                if rc != 0 { return Err(std::io::Error::last_os_error()).context("preserve desired file owner"); }
            }
        }
        writeln!(file, "# desired open_ports")?;
        writeln!(file, "# PORT TENANT SITE [tls] [cert=ID] [policy=ID]")?;
        for (port, b) in desired {
            write!(file, "{port} {} {}", b.tenant, b.site)?;
            if b.slot == REDIR_TLS as u8 { write!(file, " tls")?; }
            if let Some(cert) = &b.cert { write!(file, " cert={cert}")?; }
            if let Some(policy) = &b.policy { write!(file, " policy={policy}")?; }
            writeln!(file)?;
        }
        file.sync_all()?;
        fs::rename(&tmp, path).with_context(|| format!("replace {}", path.display()))?;
        Ok(())
    })();
    if result.is_err() { let _ = fs::remove_file(&tmp); }
    result
}

pub fn from_lists(primary: &[u16], tls: &[u16], tenant: &str, site: &str) -> Result<DesiredPorts> {
    let mut desired = DesiredPorts::new();
    for (ports, slot) in [(primary, REDIR_PRIMARY as u8), (tls, REDIR_TLS as u8)] {
        for p in ports {
            let b = PortBinding { slot, tenant: tenant.into(), site: site.into(), cert: None, policy: None };
            if desired.insert(*p, b).is_some() { bail!("port {p} is assigned to both primary and tls"); }
        }
    }
    Ok(desired)
}

pub fn plan(desired: &DesiredPorts, current: &HashMap<u16, u8>) -> ReconcilePlan {
    let mut plan = ReconcilePlan::default();
    for (port, binding) in desired {
        if current.get(port) != Some(&binding.slot) {
            if binding.slot == REDIR_TLS as u8 { plan.put_tls.push(*port); } else { plan.put_primary.push(*port); }
        }
    }
    for port in current.keys() { if !desired.contains_key(port) { plan.delete.push(*port); } }
    plan.delete.sort_unstable(); plan
}

pub fn read_map(map: &(impl MapCore + ?Sized)) -> Result<HashMap<u16, u8>> {
    let mut current = HashMap::new();
    for key in map.keys() {
        let port = match key.as_slice() { [a,b,..] => u16::from_ne_bytes([*a,*b]), [a] => u16::from(*a), _ => continue };
        let value = map.lookup(&key, MapFlags::ANY)?.unwrap_or_default();
        current.insert(port, value.first().copied().unwrap_or(0));
    }
    Ok(current)
}

pub fn reconcile_map(map: &(impl MapCore + ?Sized), desired: &DesiredPorts) -> Result<ReconcilePlan> {
    let plan = plan(desired, &read_map(map)?);
    for (ports, slot) in [(&plan.put_primary, REDIR_PRIMARY as u8), (&plan.put_tls, REDIR_TLS as u8)] {
        for port in ports {
            let mut key=vec![0;map.key_size() as usize]; let n=key.len().min(2); key[..n].copy_from_slice(&port.to_ne_bytes()[..n]);
            let mut value=vec![0;map.value_size() as usize]; if let Some(first)=value.first_mut(){*first=slot;}
            map.update(&key,&value,MapFlags::ANY).with_context(|| format!("open_ports put {port}"))?;
        }
    }
    for port in &plan.delete { let mut key=vec![0;map.key_size() as usize]; let n=key.len().min(2); key[..n].copy_from_slice(&port.to_ne_bytes()[..n]); map.delete(&key).with_context(|| format!("open_ports delete {port}"))?; }
    Ok(plan)
}

#[cfg(test)] mod tests {
    use super::*; use std::io::Cursor;
    #[test] fn parses_comments_ranges_commas_and_tls() {
        let got=load_from_reader(Cursor::new("# desired\n18081,18082 acme www\n20000-20001 acme api\n18443 acme www tls cert=www policy=default # fallback\n")).unwrap();
        assert_eq!(got.get(&18081).unwrap().slot,REDIR_PRIMARY as u8); assert_eq!(got.get(&20001).unwrap().site,"api"); assert_eq!(got.get(&18443).unwrap().slot,REDIR_TLS as u8);
    }
    #[test] fn old_format_and_missing_binding_are_rejected() { for line in ["18081\n","18443 tls\n","18081 acme\n"] { let e=load_from_reader(Cursor::new(line)).unwrap_err().to_string(); assert!(e.contains("binding")&&e.contains("docs/binding.md")); } }
    #[test] fn plans_missing_wrong_slot_and_extra() {
        let desired=from_lists(&[10010,10011],&[10012],"acme","www").unwrap(); let current=HashMap::from([(10010,REDIR_PRIMARY as u8),(10012,REDIR_PRIMARY as u8),(10013,REDIR_PRIMARY as u8)]);
        assert_eq!(plan(&desired,&current),ReconcilePlan{put_primary:vec![10011],put_tls:vec![10012],delete:vec![10013]});
    }
    #[test] fn reconcile_refuses_unbound_desired() {
        // load() is the reconcile/apply gate: an unbound file never produces a plan.
        assert!(load_from_reader(Cursor::new("18081\n")).is_err());
        assert!(load_from_reader(Cursor::new("18443 tls\n")).is_err());
        let denied = format!("{:#}", load_from_reader(Cursor::new("6379 acme www\n")).unwrap_err());
        assert!(denied.contains("denied") || denied.contains("6379"), "{denied}");
    }
}
