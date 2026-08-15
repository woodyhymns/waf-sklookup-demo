//! Central desired-state contract and local cache materialization.

use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::desired::{self, DesiredPorts, PortBinding};
use crate::pin::{OPEN_PORTS_MAX_ENTRIES, REDIR_PRIMARY, REDIR_TLS};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CentralState {
    version: u32,
    ports: Vec<CentralPort>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CentralPort {
    tenant: String,
    site: String,
    port: u16,
    #[serde(default)]
    cert: Option<String>,
    #[serde(default)]
    policy: Option<String>,
    #[serde(default)]
    tls: bool,
}

pub fn load_from_str(raw: &str) -> Result<DesiredPorts> {
    let state: CentralState = serde_json::from_str(raw).context("parse central desired state JSON")?;
    if state.version != 1 { bail!("unsupported central desired state version {} (want 1)", state.version); }
    let mut desired = DesiredPorts::new();
    for entry in state.ports {
        if entry.port == 0 { bail!("central desired state port 0 is invalid"); }
        let binding = PortBinding {
            slot: if entry.tls { REDIR_TLS as u8 } else { REDIR_PRIMARY as u8 },
            tenant: entry.tenant,
            site: entry.site,
            cert: entry.cert,
            policy: entry.policy,
        };
        if let Some(old) = desired.insert(entry.port, binding.clone()) {
            if old != binding { bail!("central desired state port {} has conflicting bindings", entry.port); }
        }
    }
    if desired.len() > OPEN_PORTS_MAX_ENTRIES as usize {
        bail!("central desired state has {} ports; open_ports max_entries is {OPEN_PORTS_MAX_ENTRIES}", desired.len());
    }
    Ok(desired)
}

pub fn load(path: &Path) -> Result<DesiredPorts> {
    let raw = fs::read_to_string(path).with_context(|| format!("read central desired state {}", path.display()))?;
    load_from_str(&raw).with_context(|| format!("load central desired state {}", path.display()))
}

pub fn apply_cache(central_path: &Path, ports_file: &Path, policy_file: &Path) -> Result<DesiredPorts> {
    let desired = load(central_path)?;
    let policy = crate::policy::load(policy_file)?;
    crate::policy::validate(&desired, &policy)?;
    desired::write(ports_file, &desired)?;
    Ok(desired)
}

pub fn write(path: &Path, desired: &DesiredPorts) -> Result<()> {
    let state = CentralState { version: 1, ports: desired.iter().map(|(port, b)| CentralPort {
        tenant: b.tenant.clone(), site: b.site.clone(), port: *port, cert: b.cert.clone(),
        policy: b.policy.clone(), tls: b.slot == REDIR_TLS as u8,
    }).collect() };
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) { fs::create_dir_all(parent)?; }
    fs::write(path, serde_json::to_vec_pretty(&state)?).with_context(|| format!("write central desired state {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let n = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        std::env::temp_dir().join(format!("waf-central-{label}-{}-{n}", std::process::id()))
    }

    #[test]
    fn apply_writes_cache_only_after_whole_state_validates() {
        let dir = temp_dir("apply");
        fs::create_dir_all(&dir).unwrap();
        let central = dir.join("central.json");
        let cache = dir.join("ports.conf");
        let policy = dir.join("policy.conf");
        fs::write(&policy, "allow_privileged=\nmax_ports_per_tenant=32\nmax_ports_per_machine=128\n").unwrap();
        fs::write(&central, r#"{"version":1,"ports":[{"tenant":"demo","site":"local","port":18081},{"tenant":"demo","site":"local","port":18443,"tls":true,"cert":"local","policy":"default"}]}"#).unwrap();
        let got = apply_cache(&central, &cache, &policy).unwrap();
        assert_eq!(got.len(), 2);
        let text = fs::read_to_string(&cache).unwrap();
        assert!(text.contains("18081 demo local"));
        assert!(text.contains("18443 demo local tls cert=local policy=default"));

        let before = text;
        for bad in [
            r#"{"version":1,"ports":[{"site":"local","port":18082}]}"#,
            r#"{"version":1,"ports":[{"tenant":"","site":"local","port":18082}]}"#,
            r#"{"version":1,"ports":[{"tenant":"demo","site":"local","port":6379}]}"#,
            r#"{"version":1,"ports":[{"tenant":"demo","site":"local","port":80}]}"#,
        ] {
            fs::write(&central, bad).unwrap();
            assert!(apply_cache(&central, &cache, &policy).is_err());
            assert_eq!(fs::read_to_string(&cache).unwrap(), before);
        }
        fs::remove_dir_all(dir).unwrap();
    }
}
