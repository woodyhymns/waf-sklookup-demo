//! File-backed desired state for `open_ports`.

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use anyhow::{bail, Context, Result};
use libbpf_rs::{MapCore, MapFlags};

use crate::pin::{OPEN_PORTS_MAX_ENTRIES, REDIR_PRIMARY, REDIR_TLS};
use crate::ports::parse_port_list_flexible;

pub type DesiredPorts = BTreeMap<u16, u8>;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReconcilePlan {
    pub put_primary: Vec<u16>,
    pub put_tls: Vec<u16>,
    pub delete: Vec<u16>,
}

pub fn load(path: &Path) -> Result<DesiredPorts> {
    let file = File::open(path)
        .with_context(|| format!("open desired ports file {}", path.display()))?;
    load_from_reader(file).with_context(|| format!("read desired ports file {}", path.display()))
}

pub fn load_from_reader(reader: impl std::io::Read) -> Result<DesiredPorts> {
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
        let mut fields = line.split_whitespace();
        let spec = fields.next().unwrap();
        let slot = match fields.next() {
            None => REDIR_PRIMARY as u8,
            Some("tls") => REDIR_TLS as u8,
            Some(other) => {
                bail!("line {line_no}: unexpected token {other:?} (only `tls` is allowed)")
            }
        };
        if let Some(other) = fields.next() {
            bail!("line {line_no}: unexpected token {other:?}");
        }
        for port in parse_port_list_flexible(spec).with_context(|| format!("line {line_no}"))? {
            if let Some(old) = desired.insert(port, slot) {
                if old != slot {
                    bail!("line {line_no}: port {port} is assigned to both primary and tls");
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
    Ok(desired)
}

pub fn write(path: &Path, desired: &DesiredPorts) -> Result<()> {
    let old_metadata = fs::metadata(path).ok();
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("ports.conf");
    let tmp = parent.join(format!(".{name}.tmp.{}", std::process::id()));
    let result = (|| -> Result<()> {
        let mut file = File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
        #[cfg(unix)]
        if let Some(metadata) = &old_metadata {
            file.set_permissions(fs::Permissions::from_mode(metadata.mode()))?;
            if unsafe { libc::geteuid() } == 0 {
                let rc = unsafe {
                    libc::fchown(file.as_raw_fd(), metadata.uid(), metadata.gid())
                };
                if rc != 0 {
                    return Err(std::io::Error::last_os_error())
                        .context("preserve desired file owner");
                }
            }
        }
        writeln!(file, "# desired open_ports")?;
        for (port, slot) in desired {
            if *slot == REDIR_TLS as u8 {
                writeln!(file, "{port} tls")?;
            } else {
                writeln!(file, "{port}")?;
            }
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

pub fn from_lists(primary: &[u16], tls: &[u16]) -> Result<DesiredPorts> {
    let mut desired = DesiredPorts::new();
    for p in primary {
        desired.insert(*p, REDIR_PRIMARY as u8);
    }
    for p in tls {
        if desired.insert(*p, REDIR_TLS as u8).is_some() {
            bail!("port {p} is assigned to both primary and tls");
        }
    }
    Ok(desired)
}

pub fn plan(desired: &DesiredPorts, current: &HashMap<u16, u8>) -> ReconcilePlan {
    let mut plan = ReconcilePlan::default();
    for (port, slot) in desired {
        if current.get(port) != Some(slot) {
            if *slot == REDIR_TLS as u8 {
                plan.put_tls.push(*port);
            } else {
                plan.put_primary.push(*port);
            }
        }
    }
    for port in current.keys() {
        if !desired.contains_key(port) {
            plan.delete.push(*port);
        }
    }
    plan.delete.sort_unstable();
    plan
}

pub fn read_map(map: &impl MapCore) -> Result<HashMap<u16, u8>> {
    let mut current = HashMap::new();
    for key in map.keys() {
        let port = match key.as_slice() {
            [a, b, ..] => u16::from_ne_bytes([*a, *b]),
            [a] => u16::from(*a),
            _ => continue,
        };
        let value = map.lookup(&key, MapFlags::ANY)?.unwrap_or_default();
        current.insert(port, value.first().copied().unwrap_or(0));
    }
    Ok(current)
}

/// Reconcile any loaded `open_ports` map. Pinned-map ctl uses the batched variant in `ctl`.
pub fn reconcile_map(map: &impl MapCore, desired: &DesiredPorts) -> Result<ReconcilePlan> {
    let plan = plan(desired, &read_map(map)?);
    for (ports, slot) in [
        (&plan.put_primary, REDIR_PRIMARY as u8),
        (&plan.put_tls, REDIR_TLS as u8),
    ] {
        for port in ports {
            let mut key = vec![0; map.key_size() as usize];
            let n = key.len().min(2);
            key[..n].copy_from_slice(&port.to_ne_bytes()[..n]);
            let mut value = vec![0; map.value_size() as usize];
            if let Some(first) = value.first_mut() {
                *first = slot;
            }
            map.update(&key, &value, MapFlags::ANY)
                .with_context(|| format!("open_ports put {port}"))?;
        }
    }
    for port in &plan.delete {
        let mut key = vec![0; map.key_size() as usize];
        let n = key.len().min(2);
        key[..n].copy_from_slice(&port.to_ne_bytes()[..n]);
        map.delete(&key).with_context(|| format!("open_ports delete {port}"))?;
    }
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn parses_comments_ranges_commas_and_tls() {
        let got = load_from_reader(Cursor::new(
            "# desired\n18081,18082\n20000-20001\n18443 tls # fallback\n",
        ))
        .unwrap();
        assert_eq!(got.get(&18081), Some(&(REDIR_PRIMARY as u8)));
        assert_eq!(got.get(&20001), Some(&(REDIR_PRIMARY as u8)));
        assert_eq!(got.get(&18443), Some(&(REDIR_TLS as u8)));
    }

    #[test]
    fn plans_missing_wrong_slot_and_extra() {
        let desired = from_lists(&[10, 11], &[12]).unwrap();
        let current = HashMap::from([
            (10, REDIR_PRIMARY as u8),
            (12, REDIR_PRIMARY as u8),
            (13, REDIR_PRIMARY as u8),
        ]);
        assert_eq!(
            plan(&desired, &current),
            ReconcilePlan {
                put_primary: vec![11],
                put_tls: vec![12],
                delete: vec![13]
            }
        );
    }
}
