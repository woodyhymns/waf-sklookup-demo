//! Runtime endpoint reservations shared by the attached loader and detached ctl.
//!
//! A pinned BPF map alone does not describe management listeners selected by
//! long-running CLI arguments. This sidecar is deliberately stored under /run,
//! never below bpffs: BPF filesystems accept BPF objects, not ordinary JSON.

use std::collections::BTreeSet;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::key::Dest;
use crate::policy::{Policy, ReservedEndpoint};

const MANIFEST_SCHEMA_VERSION: u32 = 1;
const MANIFEST_DIR: &str = "/run/waf-sklookup/reservations";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeReservationManifest {
    pub schema_version: u32,
    pub pin_dir: String,
    pub endpoints: Vec<ReservedEndpoint>,
    pub generation: String,
}

/// Bounded DFX view suitable for status/Prometheus labels. Endpoint addresses
/// and parser errors deliberately stay out of this structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservationSummary {
    pub state: &'static str,
    pub generation: Option<String>,
    pub endpoint_count: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct WireManifest {
    schema_version: u32,
    pin_dir: String,
    endpoints: Vec<WireEndpoint>,
    generation: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct WireEndpoint {
    port: u16,
    destination: String,
    source: String,
}

fn pin_name_hash(pin_dir: &Path) -> String {
    // Stable, dependency-free FNV-1a filename discriminator. It is an object
    // namespace key, not a security primitive; the full pin_dir is validated in
    // the manifest body before detached ctl can use it.
    let mut hash = 0xcbf29ce484222325u64;
    for byte in pin_dir.as_os_str().as_encoded_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

fn manifest_path_in(sidecar_dir: &Path, pin_dir: &Path) -> PathBuf {
    let leaf = pin_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("waf-sklookup");
    sidecar_dir.join(format!("{leaf}-{}.json", pin_name_hash(pin_dir)))
}

pub fn manifest_path_for(pin_dir: &Path) -> PathBuf {
    manifest_path_in(Path::new(MANIFEST_DIR), pin_dir)
}

impl RuntimeReservationManifest {
    pub fn new(pin_dir: &Path, endpoints: Vec<ReservedEndpoint>) -> Self {
        let endpoints: Vec<_> = endpoints
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let pin_dir = pin_dir.to_string_lossy().into_owned();
        let generation = generation(&pin_dir, &endpoints);
        Self {
            schema_version: MANIFEST_SCHEMA_VERSION,
            pin_dir,
            endpoints,
            generation,
        }
    }
}

fn generation(pin_dir: &str, endpoints: &[ReservedEndpoint]) -> String {
    let mut material = String::from(pin_dir);
    for endpoint in endpoints {
        material.push('|');
        material.push_str(&endpoint.dest.to_string());
        material.push(':');
        material.push_str(&endpoint.port.to_string());
        material.push(':');
        material.push_str(&endpoint.source);
    }
    pin_name_hash(Path::new(&material))
}

fn to_wire(manifest: &RuntimeReservationManifest) -> WireManifest {
    WireManifest {
        schema_version: manifest.schema_version,
        pin_dir: manifest.pin_dir.clone(),
        endpoints: manifest
            .endpoints
            .iter()
            .map(|endpoint| WireEndpoint {
                port: endpoint.port,
                destination: endpoint.dest.to_string(),
                source: endpoint.source.clone(),
            })
            .collect(),
        generation: manifest.generation.clone(),
    }
}

fn from_wire(expected_pin: &Path, wire: WireManifest) -> Result<RuntimeReservationManifest> {
    if wire.schema_version != MANIFEST_SCHEMA_VERSION {
        bail!(
            "runtime reservation manifest schema={} want={MANIFEST_SCHEMA_VERSION}; restart the attached loader",
            wire.schema_version
        );
    }
    let expected = expected_pin.to_string_lossy();
    if wire.pin_dir != expected {
        bail!(
            "runtime reservation manifest pin_dir={:?} does not match requested pin_dir={expected:?}; refuse detached mutation",
            wire.pin_dir
        );
    }
    let mut endpoints = BTreeSet::new();
    for endpoint in wire.endpoints {
        if endpoint.port == 0
            || endpoint.source.is_empty()
            || endpoint.source.chars().any(char::is_whitespace)
        {
            bail!("runtime reservation manifest has invalid endpoint metadata");
        }
        let dest = Dest::parse(&endpoint.destination).with_context(|| {
            format!(
                "invalid runtime reservation destination {:?}",
                endpoint.destination
            )
        })?;
        endpoints.insert(ReservedEndpoint {
            port: endpoint.port,
            dest,
            source: endpoint.source,
        });
    }
    let endpoints: Vec<_> = endpoints.into_iter().collect();
    let expected_generation = generation(&wire.pin_dir, &endpoints);
    if wire.generation != expected_generation {
        bail!("runtime reservation manifest generation mismatch; refuse detached mutation");
    }
    Ok(RuntimeReservationManifest {
        schema_version: wire.schema_version,
        pin_dir: wire.pin_dir,
        endpoints,
        generation: wire.generation,
    })
}

fn write_in(
    sidecar_dir: &Path,
    pin_dir: &Path,
    endpoints: Vec<ReservedEndpoint>,
) -> Result<RuntimeReservationManifest> {
    let manifest = RuntimeReservationManifest::new(pin_dir, endpoints);
    let path = manifest_path_in(sidecar_dir, pin_dir);
    let parent = path
        .parent()
        .context("runtime reservation manifest has no parent")?;
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let tmp = path.with_extension("tmp");
    let json = serde_json::to_vec_pretty(&to_wire(&manifest))
        .context("serialize runtime reservation manifest")?;
    fs::write(&tmp, json).with_context(|| format!("write {}", tmp.display()))?;
    fs::rename(&tmp, &path).with_context(|| format!("replace {}", path.display()))?;
    Ok(manifest)
}

pub fn write(
    pin_dir: &Path,
    endpoints: Vec<ReservedEndpoint>,
) -> Result<RuntimeReservationManifest> {
    write_in(Path::new(MANIFEST_DIR), pin_dir, endpoints)
}

fn read_in(sidecar_dir: &Path, pin_dir: &Path) -> Result<Option<RuntimeReservationManifest>> {
    let path = manifest_path_in(sidecar_dir, pin_dir);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).with_context(|| format!("read {}", path.display())),
    };
    let wire: WireManifest =
        serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))?;
    from_wire(pin_dir, wire).map(Some)
}

pub fn read(pin_dir: &Path) -> Result<Option<RuntimeReservationManifest>> {
    read_in(Path::new(MANIFEST_DIR), pin_dir)
}

pub fn reservation_summary(
    result: Result<Option<RuntimeReservationManifest>>,
) -> ReservationSummary {
    match result {
        Ok(Some(manifest)) => ReservationSummary {
            state: "active",
            generation: Some(manifest.generation),
            endpoint_count: manifest.endpoints.len(),
        },
        Ok(None) => ReservationSummary {
            state: "missing",
            generation: None,
            endpoint_count: 0,
        },
        // Do not expose arbitrary parser/path error text to a metrics label or
        // JSON status field. Operators can inspect the local audit log instead.
        Err(_) => ReservationSummary {
            state: "invalid",
            generation: None,
            endpoint_count: 0,
        },
    }
}

pub fn summary(pin_dir: &Path) -> ReservationSummary {
    reservation_summary(read(pin_dir))
}

fn remove_in(sidecar_dir: &Path, pin_dir: &Path) {
    let _ = fs::remove_file(manifest_path_in(sidecar_dir, pin_dir));
}

pub fn remove(pin_dir: &Path) {
    remove_in(Path::new(MANIFEST_DIR), pin_dir);
}

/// Return an effective policy for every detached mutation path. A malformed
/// present manifest is an error (fail closed); a missing manifest preserves the
/// documented compatibility path for legacy pinned deployments.
fn effective_policy_in(
    policy_file: &Path,
    pin_dir: &Path,
    sidecar_dir: &Path,
) -> Result<(Policy, Option<RuntimeReservationManifest>)> {
    let mut policy = crate::policy::load(policy_file)?;
    let manifest = read_in(sidecar_dir, pin_dir)?;
    if let Some(manifest) = &manifest {
        policy
            .reserve_endpoints
            .extend(manifest.endpoints.iter().cloned());
    }
    Ok((policy, manifest))
}

pub fn effective_policy(
    policy_file: &Path,
    pin_dir: &Path,
) -> Result<(Policy, Option<RuntimeReservationManifest>)> {
    effective_policy_in(policy_file, pin_dir, Path::new(MANIFEST_DIR))
}

pub fn endpoint_from_socket(raw: &str, source: &str) -> Result<ReservedEndpoint> {
    if source.is_empty() || source.chars().any(char::is_whitespace) {
        bail!("runtime reservation source must be non-empty and contain no whitespace");
    }
    let socket: SocketAddr = raw
        .parse()
        .with_context(|| format!("{source} must be IP:PORT (IPv6 requires brackets): {raw:?}"))?;
    let dest = match socket.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => Dest::AnyV4,
        IpAddr::V4(ip) => Dest::V4(ip),
        IpAddr::V6(ip) if ip.is_unspecified() => Dest::AnyV6,
        IpAddr::V6(ip) => Dest::V6(ip),
    };
    Ok(ReservedEndpoint {
        port: socket.port(),
        dest,
        source: source.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    // SDD-002 / T-023: runtime reservation state must never be written below a
    // private bpffs pin directory and its source must round-trip exactly.
    #[test]
    fn private_pin_uses_run_sidecar_and_roundtrips_endpoint_source() {
        let pin = Path::new("/tmp/private-bpffs/waf-a");
        let path = manifest_path_for(pin);
        assert!(
            path.starts_with("/run/waf-sklookup/reservations"),
            "{}",
            path.display()
        );
        let endpoint = ReservedEndpoint {
            port: 9101,
            dest: Dest::V4("127.0.0.1".parse().unwrap()),
            source: "metrics-listen".into(),
        };
        let manifest = RuntimeReservationManifest::new(pin, vec![endpoint.clone()]);
        assert_eq!(manifest.endpoints, vec![endpoint]);
        assert!(!manifest.generation.is_empty());
    }

    #[test]
    fn summary_is_bounded_for_active_missing_and_invalid_manifest() {
        let pin = Path::new("/tmp/waf-summary");
        let manifest = RuntimeReservationManifest::new(
            pin,
            vec![endpoint_from_socket("127.0.0.1:9101", "metrics-listen").unwrap()],
        );
        assert_eq!(reservation_summary(Ok(Some(manifest))).state, "active");
        assert_eq!(reservation_summary(Ok(None)).state, "missing");
        assert_eq!(
            reservation_summary(Err(anyhow::anyhow!("parse 10.0.0.1:9999"))).state,
            "invalid"
        );
    }

    #[test]
    fn effective_policy_merges_manifest_without_collapsing_vips() {
        let root = std::env::temp_dir().join(format!("waf-reservation-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let policy_file = root.join("policy.conf");
        fs::write(
            &policy_file,
            "allow_privileged=\nmax_ports_per_tenant=32\nmax_ports_per_machine=128\n",
        )
        .unwrap();
        let pin = root.join("pins");
        let sidecars = root.join("sidecars");
        write_in(
            &sidecars,
            &pin,
            vec![endpoint_from_socket("127.0.0.1:9101", "metrics-listen").unwrap()],
        )
        .unwrap();

        let (policy, manifest) = effective_policy_in(&policy_file, &pin, &sidecars).unwrap();
        assert_eq!(manifest.unwrap().endpoints.len(), 1);
        let mut desired = crate::desired::DesiredPorts::new();
        desired.insert(
            crate::key::PortKey::new(9101, Dest::V4("10.0.0.10".parse().unwrap())),
            crate::desired::PortBinding::new(crate::pin::REDIR_PRIMARY as u8, "acme", "www"),
        );
        assert!(crate::policy::validate(&desired, &policy).is_ok());
        desired.clear();
        desired.insert(
            crate::key::PortKey::new(9101, Dest::V4("127.0.0.1".parse().unwrap())),
            crate::desired::PortBinding::new(crate::pin::REDIR_PRIMARY as u8, "acme", "www"),
        );
        assert!(crate::policy::validate(&desired, &policy).is_err());
        remove_in(&sidecars, &pin);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn manifest_rejects_wrong_pin_path_and_tamper() {
        let pin = Path::new("/tmp/waf-pin-a");
        let manifest = RuntimeReservationManifest::new(
            pin,
            vec![endpoint_from_socket("127.0.0.1:9101", "metrics-listen").unwrap()],
        );
        let mut wire = to_wire(&manifest);
        wire.pin_dir = "/tmp/waf-pin-b".into();
        assert!(from_wire(pin, wire).is_err());

        let mut wire = to_wire(&manifest);
        wire.generation = "tampered".into();
        assert!(from_wire(pin, wire).is_err());
    }
}
