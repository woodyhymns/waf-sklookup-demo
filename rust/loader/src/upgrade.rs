//! Single-node BPF program/link upgrade and rollback primitives (SDD-003).
//!
//! The update unit is one pinned netns `bpf_link`. Candidate objects reuse the
//! five pinned maps, so `open_ports`, worker sockmap state and telemetry remain
//! intact. A durable `/run` journal makes any in-progress state fail-closed for
//! operators and records whether rollback is still possible.

use std::fs;
use std::os::fd::{AsFd, AsRawFd};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use libbpf_rs::{AsRawLibbpf, Link, MapCore, Object, ObjectBuilder, Program};
use serde::{Deserialize, Serialize};

use crate::identity::{self, ProgramIdentity};
use crate::pin;

const SCHEMA_VERSION: u32 = 1;
// bpffs object names must remain conservative: private bpffs mounts on the
// supported kernel reject dotted names with EPERM even though the main `prog`
// pin is accepted. Keep these as portable BPF-object directory entries.
const CANDIDATE_PROG_PIN: &str = "prog_candidate";
const PREVIOUS_PROG_PIN: &str = "prog_previous";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Prepared,
    Activating,
    Healthy,
    RollingBack,
    RolledBack,
    Committed,
    Failed,
}

impl Phase {
    pub fn terminal(self) -> bool {
        matches!(self, Self::RolledBack | Self::Committed | Self::Failed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Journal {
    pub schema_version: u32,
    pub phase: Phase,
    pub old: ProgramIdentity,
    pub candidate: ProgramIdentity,
    pub health_window_ms: u64,
    pub detail: String,
}

fn journal_path(pin_dir: &Path) -> PathBuf {
    let identity = pin::identity_path(pin_dir);
    let stem = identity
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("waf-sklookup");
    identity.with_file_name(format!("upgrade-{stem}.json"))
}

fn candidate_pin_path(pin_dir: &Path) -> PathBuf {
    pin_dir.join(CANDIDATE_PROG_PIN)
}

fn previous_pin_path(pin_dir: &Path) -> PathBuf {
    pin_dir.join(PREVIOUS_PROG_PIN)
}

pub fn read_journal(pin_dir: &Path) -> Result<Option<Journal>> {
    let path = journal_path(pin_dir);
    match fs::read_to_string(&path) {
        Ok(raw) => Ok(Some(
            serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))?,
        )),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("read {}", path.display())),
    }
}

fn write_journal(pin_dir: &Path, journal: &Journal) -> Result<()> {
    let path = journal_path(pin_dir);
    let parent = path.parent().context("upgrade journal has no parent")?;
    fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
    let temp = path.with_extension("json.tmp");
    let data = serde_json::to_string(journal).context("serialize upgrade journal")?;
    fs::write(&temp, format!("{data}\n")).with_context(|| format!("write {}", temp.display()))?;
    fs::rename(&temp, &path).with_context(|| format!("replace {}", path.display()))?;
    Ok(())
}

fn mark(
    pin_dir: &Path,
    journal: &mut Journal,
    phase: Phase,
    detail: impl Into<String>,
) -> Result<()> {
    journal.phase = phase;
    journal.detail = detail.into();
    write_journal(pin_dir, journal)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapAbi {
    pub name: String,
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
}

pub fn expected_map_names() -> [&'static str; 5] {
    [
        pin::OPEN_PORTS_MAP,
        pin::REDIR_SOCKET_MAP,
        pin::STATS_MAP,
        pin::ANOMALIES_MAP,
        pin::ANOMALY_GATE_MAP,
    ]
}

fn abi_of(map: &impl MapCore) -> MapAbi {
    MapAbi {
        name: map.name().to_string_lossy().into_owned(),
        map_type: map.map_type() as u32,
        key_size: map.key_size(),
        value_size: map.value_size(),
        max_entries: map.max_entries(),
    }
}

fn validate_abi(candidate: &MapAbi, live: &MapAbi) -> Result<()> {
    if candidate != live {
        bail!(
            "incompatible map ABI for {}: candidate(type={},key={},value={},max={}) live(type={},key={},value={},max={})",
            live.name,
            candidate.map_type,
            candidate.key_size,
            candidate.value_size,
            candidate.max_entries,
            live.map_type,
            live.key_size,
            live.value_size,
            live.max_entries,
        );
    }
    Ok(())
}

/// Open a candidate object, verify every persistent map ABI, and reuse the
/// existing pinned map FD before the object is loaded. Unknown candidate maps
/// are rejected because an upgrade must not silently create state outside the
/// SDD-003 compatibility contract.
fn load_candidate(candidate: &Path, pin_dir: &Path) -> Result<Object> {
    if !candidate.is_file() {
        bail!(
            "candidate BPF object does not exist: {}",
            candidate.display()
        );
    }
    let mut open = ObjectBuilder::default()
        .open_file(candidate)
        .with_context(|| format!("open candidate {}", candidate.display()))?;
    let wanted = expected_map_names();
    let mut seen = Vec::new();
    for mut candidate_map in open.maps_mut() {
        let name = candidate_map.name().to_string_lossy().into_owned();
        if !wanted.iter().any(|expected| *expected == name) {
            bail!("candidate contains unsupported map {name}; refuse non-audited upgrade");
        }
        let live_path = match name.as_str() {
            pin::OPEN_PORTS_MAP => pin::open_ports_path(pin_dir),
            pin::REDIR_SOCKET_MAP => pin::redir_socket_path(pin_dir),
            pin::STATS_MAP => pin::stats_path(pin_dir),
            pin::ANOMALIES_MAP => pin::anomalies_path(pin_dir),
            pin::ANOMALY_GATE_MAP => pin::anomaly_gate_path(pin_dir),
            _ => unreachable!(),
        };
        let raw = candidate_map.as_libbpf_object().as_ptr();
        let candidate_abi = MapAbi {
            name: name.clone(),
            map_type: candidate_map.map_type() as u32,
            key_size: unsafe { libbpf_sys::bpf_map__key_size(raw) },
            value_size: unsafe { libbpf_sys::bpf_map__value_size(raw) },
            max_entries: candidate_map.max_entries(),
        };
        let live = libbpf_rs::MapHandle::from_pinned_path(&live_path)
            .with_context(|| format!("open pinned map {}", live_path.display()))?;
        validate_abi(&candidate_abi, &abi_of(&live))?;
        candidate_map
            .reuse_pinned_map(&live_path)
            .with_context(|| format!("reuse pinned map {}", live_path.display()))?;
        seen.push(name);
    }
    for expected in wanted {
        if !seen.iter().any(|name| name == expected) {
            bail!("candidate is missing required persistent map {expected}");
        }
    }
    let object = open
        .load()
        .context("load ABI-compatible candidate object")?;
    let open_ports = object
        .maps()
        .find(|map| map.name() == pin::OPEN_PORTS_MAP)
        .context("loaded candidate missing open_ports")?;
    pin::assert_open_ports_layout(&open_ports)?;
    let redir = object
        .maps()
        .find(|map| map.name() == pin::REDIR_SOCKET_MAP)
        .context("loaded candidate missing redir_socket")?;
    pin::assert_redir_socket_layout(&redir)?;
    Ok(object)
}

fn candidate_program(object: &mut Object) -> Result<libbpf_rs::ProgramMut<'_>> {
    object
        .progs_mut()
        .find(|program| program.name() == "dispatch")
        .context("candidate object missing dispatch program")
}

fn program_identity(program: &Program<'_>) -> Result<ProgramIdentity> {
    identity::from_prog_fd(program.as_fd().as_raw_fd())
}

fn rollback_raw(link: &Link, old_fd: i32) -> Result<()> {
    let rc =
        unsafe { libbpf_sys::bpf_link_update(link.as_fd().as_raw_fd(), old_fd, std::ptr::null()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("rollback bpf_link_update");
    }
    Ok(())
}

fn health_check(pin_dir: &Path, expected: &ProgramIdentity, window: Duration) -> Result<()> {
    // Deliberately opt-in fault injection for real-kernel rollback drills. It
    // is never set by the loader or control plane and must be supplied by the
    // test runner's environment.
    if std::env::var("WAF_UPGRADE_FAIL_HEALTH").ok().as_deref() == Some("1") {
        bail!("forced upgrade health failure");
    }
    // A bounded window is intentionally boring: it checks the live pinned
    // program identity and map ABI after the link cutover, then holds the window
    // so external traffic/alert checks can observe the new generation.
    if window > Duration::from_secs(300) {
        bail!("health window exceeds 300s safety limit");
    }
    let live = Program::fd_from_pinned_path(pin::prog_path(pin_dir))
        .context("open pinned candidate program during health check")?;
    let id = identity::from_prog_fd(live.as_raw_fd())?;
    if id.tag != expected.tag {
        bail!(
            "health check tag mismatch expected={} live={}",
            expected.tag,
            id.tag
        );
    }
    let map = libbpf_rs::MapHandle::from_pinned_path(pin::open_ports_path(pin_dir))?;
    pin::assert_open_ports_layout(&map)?;
    thread::sleep(window);
    Ok(())
}

/// Upgrade one pinned netns link without detaching it. The caller must provide
/// a BPF ELF with exactly the five persistent maps in the current ABI. On any
/// activation, pin or health failure the old program remains pinned and the
/// link is updated back before the function returns an error.
pub fn activate(pin_dir: &Path, candidate: &Path, health_window: Duration) -> Result<Journal> {
    if let Some(existing) = read_journal(pin_dir)? {
        if !existing.phase.terminal() {
            bail!(
                "upgrade journal is non-terminal ({:?}); recover before another upgrade",
                existing.phase
            );
        }
    }
    let old_fd = Program::fd_from_pinned_path(pin::prog_path(pin_dir))
        .with_context(|| format!("open live program {}", pin::prog_path(pin_dir).display()))?;
    let old = identity::from_prog_fd(old_fd.as_raw_fd())?;
    let mut object = load_candidate(candidate, pin_dir)?;
    let mut program = candidate_program(&mut object)?;
    let new = program_identity(&program)?;
    if new.tag == old.tag {
        bail!(
            "candidate tag equals live tag {}; no upgrade needed",
            new.tag
        );
    }
    let mut journal = Journal {
        schema_version: SCHEMA_VERSION,
        phase: Phase::Prepared,
        old,
        candidate: new.clone(),
        health_window_ms: health_window.as_millis() as u64,
        detail: "candidate ABI preflight passed".into(),
    };
    write_journal(pin_dir, &journal)?;

    let candidate_pin = candidate_pin_path(pin_dir);
    let previous_pin = previous_pin_path(pin_dir);
    let live_pin = pin::prog_path(pin_dir);
    let _ = fs::remove_file(&candidate_pin);
    let _ = fs::remove_file(&previous_pin);
    let mut link = Link::open(pin::link_path(pin_dir))
        .with_context(|| format!("open live link {}", pin::link_path(pin_dir).display()))?;

    // Pin before touching the live link. Some kernels reject pinning a program
    // after it became the active target of a pinned netns link; pre-pinning also
    // means a pin failure cannot cause a traffic-visible transition.
    if let Err(err) = program.pin(&candidate_pin) {
        mark(
            pin_dir,
            &mut journal,
            Phase::Failed,
            format!("candidate pin preflight failed: {err:#}"),
        )?;
        return Err(err).context("pin candidate before link update");
    }
    mark(
        pin_dir,
        &mut journal,
        Phase::Activating,
        "updating pinned netns link",
    )?;
    if let Err(err) = link.update_prog(&program) {
        let _ = fs::remove_file(&candidate_pin);
        mark(
            pin_dir,
            &mut journal,
            Phase::Failed,
            format!("link update failed: {err:#}"),
        )?;
        return Err(err).context("activate candidate link");
    }

    // Preserve the old pin until the candidate has passed its local health
    // window and its identity sidecar has been updated. Two renames allow a
    // deterministic restore if any following step fails.
    if let Err(err) =
        fs::rename(&live_pin, &previous_pin).and_then(|_| fs::rename(&candidate_pin, &live_pin))
    {
        let _ = rollback_raw(&link, old_fd.as_raw_fd());
        let _ = fs::rename(&previous_pin, &live_pin);
        let _ = fs::remove_file(&candidate_pin);
        mark(
            pin_dir,
            &mut journal,
            Phase::RolledBack,
            format!("pin swap failed: {err}"),
        )?;
        return Err(err).context("swap program pins");
    }

    mark(
        pin_dir,
        &mut journal,
        Phase::Healthy,
        "candidate link active; health window running",
    )?;
    if let Err(err) = health_check(pin_dir, &new, health_window) {
        mark(
            pin_dir,
            &mut journal,
            Phase::RollingBack,
            format!("health failed: {err:#}"),
        )?;
        let rollback = rollback_raw(&link, old_fd.as_raw_fd());
        let _ = fs::rename(&live_pin, &candidate_pin);
        let _ = fs::rename(&previous_pin, &live_pin);
        let _ = fs::remove_file(&candidate_pin);
        let _ = identity::write(pin_dir, &journal.old);
        match rollback {
            Ok(()) => mark(
                pin_dir,
                &mut journal,
                Phase::RolledBack,
                format!("health rollback: {err:#}"),
            )?,
            Err(rollback_err) => mark(
                pin_dir,
                &mut journal,
                Phase::Failed,
                format!("health={err:#}; rollback={rollback_err:#}"),
            )?,
        }
        return Err(err).context("candidate health window");
    }

    if let Err(err) = identity::write(pin_dir, &new) {
        let _ = rollback_raw(&link, old_fd.as_raw_fd());
        let _ = fs::rename(&live_pin, &candidate_pin);
        let _ = fs::rename(&previous_pin, &live_pin);
        let _ = fs::remove_file(&candidate_pin);
        let _ = identity::write(pin_dir, &journal.old);
        mark(
            pin_dir,
            &mut journal,
            Phase::RolledBack,
            format!("identity write failed: {err:#}"),
        )?;
        return Err(err).context("commit candidate identity");
    }
    let _ = fs::remove_file(&previous_pin);
    mark(
        pin_dir,
        &mut journal,
        Phase::Committed,
        "candidate promoted after health window",
    )?;
    Ok(journal)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(tag: &str) -> ProgramIdentity {
        ProgramIdentity {
            id: 1,
            tag: tag.into(),
            open_ports_key_size: crate::key::PORT_KEY_SIZE as u32,
            open_ports_value_size: crate::key::PORT_VAL_SIZE as u32,
        }
    }

    #[test]
    fn incompatible_map_abi_is_rejected() {
        let live = MapAbi {
            name: "open_ports".into(),
            map_type: 1,
            key_size: 20,
            value_size: 4,
            max_entries: 131072,
        };
        let candidate = MapAbi {
            key_size: 2,
            ..live.clone()
        };
        assert!(validate_abi(&candidate, &live)
            .unwrap_err()
            .to_string()
            .contains("incompatible map ABI"));
    }

    #[test]
    fn journal_roundtrip_is_atomic_file_contract() {
        let dir = std::env::temp_dir().join(format!("waf-upgrade-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let journal = Journal {
            schema_version: SCHEMA_VERSION,
            phase: Phase::Prepared,
            old: identity("old"),
            candidate: identity("new"),
            health_window_ms: 1000,
            detail: "test".into(),
        };
        write_journal(&dir, &journal).unwrap();
        assert_eq!(read_journal(&dir).unwrap(), Some(journal));
        let _ = fs::remove_dir_all(&dir);
    }
}
