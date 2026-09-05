//! SDD-003: single-node BPF program replace + rollback on the main ABI.
//!
//! One pinned netns `bpf_link` (`sk_lookup`) is the update unit. The candidate
//! reuses pinned `open_ports` + `redir_socket` (u16 key, 2-slot SOCKMAP).
//! `bpf_link_update` avoids a detach window. The backup link is never updated
//! here. Rewrite of the SDD-003 idea against current `dispatch.bpf.c`; not the
//! #37 64-shard / 20-byte dest-key ABI.

use std::ffi::CString;
use std::fs::{self, File};
use std::hash::{Hash, Hasher};
use std::io::{self, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use libbpf_rs::{AsRawLibbpf, Link, MapCore, Object, ObjectBuilder};
use serde::{Deserialize, Serialize};

use crate::pin;

const SCHEMA_VERSION: u32 = 1;
const DEFAULT_JOURNAL_DIR: &str = "/run/waf-sklookup/upgrades";
const MAX_HEALTH_WINDOW: Duration = Duration::from_secs(300);

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
    pub pin_dir: String,
    pub candidate: String,
    pub health_window_ms: u64,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapAbi {
    pub name: String,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
}

pub fn expected_map_names() -> [&'static str; 2] {
    [pin::OPEN_PORTS_MAP, pin::REDIR_SOCKET_MAP]
}

pub fn expected_open_ports_abi() -> MapAbi {
    MapAbi {
        name: pin::OPEN_PORTS_MAP.into(),
        key_size: pin::OPEN_PORTS_KEY_SIZE,
        value_size: pin::OPEN_PORTS_VALUE_SIZE,
        max_entries: pin::OPEN_PORTS_MAX_ENTRIES,
    }
}

pub fn expected_redir_socket_abi() -> MapAbi {
    MapAbi {
        name: pin::REDIR_SOCKET_MAP.into(),
        key_size: pin::REDIR_SOCKET_KEY_SIZE,
        value_size: pin::REDIR_SOCKET_VALUE_SIZE,
        max_entries: pin::REDIR_SOCKET_MAX_ENTRIES,
    }
}

pub fn journal_path(pin_dir: &Path) -> PathBuf {
    journal_path_in(Path::new(DEFAULT_JOURNAL_DIR), pin_dir)
}

fn journal_path_in(journal_dir: &Path, pin_dir: &Path) -> PathBuf {
    journal_dir.join(format!("{}.json", pin_dir_key(pin_dir)))
}

fn pin_dir_key(pin_dir: &Path) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    pin_dir.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

pub fn read_journal(pin_dir: &Path) -> Result<Option<Journal>> {
    read_journal_at(&journal_path(pin_dir))
}

fn read_journal_at(path: &Path) -> Result<Option<Journal>> {
    match fs::read_to_string(path) {
        Ok(raw) => Ok(Some(
            serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))?,
        )),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("read {}", path.display())),
    }
}

fn write_journal(pin_dir: &Path, journal: &Journal) -> Result<()> {
    write_journal_at(&journal_path(pin_dir), journal)
}

fn write_journal_at(path: &Path, journal: &Journal) -> Result<()> {
    let parent = path.parent().context("upgrade journal has no parent")?;
    fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
    let temp = path.with_extension("json.tmp");
    let data = serde_json::to_string(journal).context("serialize upgrade journal")?;
    {
        let mut file = File::create(&temp).with_context(|| format!("create {}", temp.display()))?;
        file.write_all(data.as_bytes())
            .and_then(|_| file.write_all(b"\n"))
            .with_context(|| format!("write {}", temp.display()))?;
        file.sync_all()
            .with_context(|| format!("fsync {}", temp.display()))?;
    }
    fs::rename(&temp, path).with_context(|| format!("replace {}", path.display()))?;
    Ok(())
}

fn mark(pin_dir: &Path, journal: &mut Journal, phase: Phase, detail: impl Into<String>) -> Result<()> {
    journal.phase = phase;
    journal.detail = detail.into();
    write_journal(pin_dir, journal)
}

pub fn validate_abi(candidate: &MapAbi, expected: &MapAbi) -> Result<()> {
    if candidate != expected {
        bail!(
            "incompatible map ABI for {}: candidate(key={},value={},max={}) want(key={},value={},max={}) (main ABI; not #37 dest-key/shard)",
            expected.name,
            candidate.key_size,
            candidate.value_size,
            candidate.max_entries,
            expected.key_size,
            expected.value_size,
            expected.max_entries,
        );
    }
    Ok(())
}

fn abi_of_pinned(path: &Path, expected_name: &str) -> Result<MapAbi> {
    let map = libbpf_rs::MapHandle::from_pinned_path(path)
        .with_context(|| format!("open pinned map {}", path.display()))?;
    Ok(MapAbi {
        name: expected_name.to_string(),
        key_size: map.key_size(),
        value_size: map.value_size(),
        max_entries: map.max_entries(),
    })
}

fn open_map_abi(map: &libbpf_rs::OpenMapMut<'_>) -> MapAbi {
    let raw = map.as_libbpf_object().as_ptr();
    MapAbi {
        name: map.name().to_string_lossy().into_owned(),
        key_size: unsafe { libbpf_sys::bpf_map__key_size(raw) },
        value_size: unsafe { libbpf_sys::bpf_map__value_size(raw) },
        max_entries: map.max_entries(),
    }
}

fn load_candidate(candidate: &Path, pin_dir: &Path) -> Result<Object> {
    if !candidate.is_file() {
        bail!("candidate BPF object does not exist: {}", candidate.display());
    }
    let mut open = ObjectBuilder::default()
        .open_file(candidate)
        .with_context(|| format!("open candidate {}", candidate.display()))?;
    let wanted = expected_map_names();
    let mut seen = Vec::new();
    for mut candidate_map in open.maps_mut() {
        let name = candidate_map.name().to_string_lossy().into_owned();
        if !wanted.iter().any(|expected| *expected == name) {
            bail!(
                "candidate contains unsupported map {name}; refuse non-audited upgrade (main ABI is open_ports + redir_socket only)"
            );
        }
        let (live_path, expected) = match name.as_str() {
            n if n == pin::OPEN_PORTS_MAP => (pin::open_ports_path(pin_dir), expected_open_ports_abi()),
            n if n == pin::REDIR_SOCKET_MAP => {
                (pin::redir_socket_path(pin_dir), expected_redir_socket_abi())
            }
            _ => unreachable!("wanted-map filter"),
        };
        let candidate_abi = open_map_abi(&candidate_map);
        validate_abi(&candidate_abi, &expected)?;
        let live = abi_of_pinned(&live_path, &name)?;
        validate_abi(&live, &expected)?;
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
        .context("load ABI-compatible candidate object (verifier/attach preflight)")?;
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

fn open_pinned_prog_fd(path: &Path) -> Result<OwnedFd> {
    let s = path
        .to_str()
        .with_context(|| format!("pin path {} is not UTF-8", path.display()))?;
    let c_path = CString::new(s).with_context(|| format!("pin path {}", path.display()))?;
    let fd = unsafe { libbpf_sys::bpf_obj_get(c_path.as_ptr()) };
    if fd < 0 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("open pinned program {}", path.display()));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn link_update_fd(link: &Link, prog_fd: i32) -> Result<()> {
    let rc = unsafe {
        libbpf_sys::bpf_link_update(link.as_fd().as_raw_fd(), prog_fd, std::ptr::null())
    };
    if rc != 0 {
        return Err(io::Error::last_os_error()).context("bpf_link_update");
    }
    Ok(())
}

fn health_check(pin_dir: &Path, window: Duration) -> Result<()> {
    if std::env::var("WAF_UPGRADE_FAIL_HEALTH").ok().as_deref() == Some("1") {
        bail!("forced upgrade health failure");
    }
    if window > MAX_HEALTH_WINDOW {
        bail!("health window exceeds 300s safety limit");
    }
    if !pin::link_pinned(pin_dir) {
        bail!("primary sk_lookup link missing during health window");
    }
    let open_ports = libbpf_rs::MapHandle::from_pinned_path(pin::open_ports_path(pin_dir))?;
    pin::assert_open_ports_layout(&open_ports)?;
    let redir = libbpf_rs::MapHandle::from_pinned_path(pin::redir_socket_path(pin_dir))?;
    pin::assert_redir_socket_layout(&redir)?;
    let _ = open_pinned_prog_fd(&pin::prog_path(pin_dir))?;
    thread::sleep(window);
    Ok(())
}

fn require_live_pins(pin_dir: &Path) -> Result<()> {
    if !pin::maps_pinned(pin_dir) {
        bail!(
            "pinned maps missing under {} (need open_ports + redir_socket)",
            pin_dir.display()
        );
    }
    if !pin::link_pinned(pin_dir) {
        bail!(
            "primary sk_lookup link missing at {}",
            pin::sk_lookup_link_path(pin_dir).display()
        );
    }
    if !pin::prog_path(pin_dir).exists() {
        bail!(
            "pinned program missing at {} (restart the loader once to pin prog)",
            pin::prog_path(pin_dir).display()
        );
    }
    Ok(())
}

/// Replace the primary pinned link's program. Backup link is not touched.
pub fn activate(pin_dir: &Path, candidate: &Path, health_window: Duration) -> Result<Journal> {
    if let Some(existing) = read_journal(pin_dir)? {
        if !existing.phase.terminal() {
            bail!(
                "upgrade journal is non-terminal ({:?}); recover with upgrade-rollback before another upgrade",
                existing.phase
            );
        }
    }
    require_live_pins(pin_dir)?;
    let old_fd = open_pinned_prog_fd(&pin::prog_path(pin_dir))?;
    let object = match load_candidate(candidate, pin_dir) {
        Ok(obj) => obj,
        Err(err) => {
            let mut journal = Journal {
                schema_version: SCHEMA_VERSION,
                phase: Phase::Failed,
                pin_dir: pin_dir.display().to_string(),
                candidate: candidate.display().to_string(),
                health_window_ms: health_window.as_millis() as u64,
                detail: format!("preflight failed: {err:#}"),
            };
            let _ = write_journal(pin_dir, &journal);
            journal.phase = Phase::Failed;
            return Err(err).context("candidate preflight (live link unchanged)");
        }
    };
    let mut program = object
        .progs_mut()
        .find(|program| program.name() == "dispatch")
        .context("candidate object missing dispatch program")?;

    let mut journal = Journal {
        schema_version: SCHEMA_VERSION,
        phase: Phase::Prepared,
        pin_dir: pin_dir.display().to_string(),
        candidate: candidate.display().to_string(),
        health_window_ms: health_window.as_millis() as u64,
        detail: "candidate ABI preflight passed".into(),
    };
    write_journal(pin_dir, &journal)?;

    let candidate_pin = pin::prog_candidate_path(pin_dir);
    let previous_pin = pin::prog_previous_path(pin_dir);
    let live_pin = pin::prog_path(pin_dir);
    let _ = fs::remove_file(&candidate_pin);
    let mut link = Link::open(pin::sk_lookup_link_path(pin_dir)).with_context(|| {
        format!(
            "open live link {}",
            pin::sk_lookup_link_path(pin_dir).display()
        )
    })?;

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
        "updating pinned primary netns link",
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

    if let Err(err) =
        fs::rename(&live_pin, &previous_pin).and_then(|_| fs::rename(&candidate_pin, &live_pin))
    {
        let _ = link_update_fd(&link, old_fd.as_raw_fd());
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
    if let Err(err) = health_check(pin_dir, health_window) {
        mark(
            pin_dir,
            &mut journal,
            Phase::RollingBack,
            format!("health failed: {err:#}"),
        )?;
        let rollback = link_update_fd(&link, old_fd.as_raw_fd());
        let _ = fs::rename(&live_pin, &candidate_pin);
        let _ = fs::rename(&previous_pin, &live_pin);
        let _ = fs::remove_file(&candidate_pin);
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

    mark(
        pin_dir,
        &mut journal,
        Phase::Committed,
        "candidate promoted after health window (prog_previous retained)",
    )?;
    Ok(journal)
}

/// Restore `prog_previous` onto the primary link, or clear a never-activated journal.
pub fn rollback(pin_dir: &Path) -> Result<Journal> {
    let mut journal = read_journal(pin_dir)?.unwrap_or(Journal {
        schema_version: SCHEMA_VERSION,
        phase: Phase::Prepared,
        pin_dir: pin_dir.display().to_string(),
        candidate: String::new(),
        health_window_ms: 0,
        detail: "no journal; explicit rollback".into(),
    });
    let previous = pin::prog_previous_path(pin_dir);
    let live = pin::prog_path(pin_dir);
    let candidate_pin = pin::prog_candidate_path(pin_dir);
    if !previous.exists() {
        let _ = fs::remove_file(&candidate_pin);
        mark(
            pin_dir,
            &mut journal,
            Phase::RolledBack,
            "no prog_previous; candidate pin cleared (live link unchanged)",
        )?;
        return Ok(journal);
    }
    if !pin::link_pinned(pin_dir) {
        bail!(
            "cannot rollback: primary sk_lookup link missing at {}",
            pin::sk_lookup_link_path(pin_dir).display()
        );
    }
    mark(
        pin_dir,
        &mut journal,
        Phase::RollingBack,
        "explicit rollback to prog_previous",
    )?;
    let old_fd = open_pinned_prog_fd(&previous)?;
    let link = Link::open(pin::sk_lookup_link_path(pin_dir))?;
    if let Err(err) = link_update_fd(&link, old_fd.as_raw_fd()) {
        mark(
            pin_dir,
            &mut journal,
            Phase::Failed,
            format!("explicit rollback bpf_link_update failed: {err:#}"),
        )?;
        return Err(err);
    }
    if live.exists() {
        let _ = fs::rename(&live, &candidate_pin);
    }
    fs::rename(&previous, &live)
        .with_context(|| format!("restore {}", live.display()))?;
    let _ = fs::remove_file(&candidate_pin);
    mark(
        pin_dir,
        &mut journal,
        Phase::RolledBack,
        "primary link restored to prog_previous",
    )?;
    Ok(journal)
}

pub fn status(pin_dir: &Path) -> Result<serde_json::Value> {
    let journal = read_journal(pin_dir)?;
    Ok(serde_json::json!({
        "pin_dir": pin_dir.display().to_string(),
        "primary_link": pin::link_pinned(pin_dir),
        "backup_link": pin::backup_link_pinned(pin_dir),
        "maps": pin::maps_pinned(pin_dir),
        "prog": pin::prog_path(pin_dir).exists(),
        "prog_previous": pin::prog_previous_path(pin_dir).exists(),
        "journal": journal,
        "abi": {
            "open_ports_key": pin::OPEN_PORTS_KEY_SIZE,
            "open_ports_value": pin::OPEN_PORTS_VALUE_SIZE,
            "redir_socket_slots": pin::REDIR_SOCKET_MAX_ENTRIES,
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_journal(phase: Phase) -> Journal {
        Journal {
            schema_version: SCHEMA_VERSION,
            phase,
            pin_dir: "/sys/fs/bpf/waf-sklookup".into(),
            candidate: "/tmp/dispatch.bpf.o".into(),
            health_window_ms: 1000,
            detail: "test".into(),
        }
    }

    #[test]
    fn terminal_phases() {
        assert!(!Phase::Prepared.terminal());
        assert!(!Phase::Activating.terminal());
        assert!(!Phase::Healthy.terminal());
        assert!(!Phase::RollingBack.terminal());
        assert!(Phase::RolledBack.terminal());
        assert!(Phase::Committed.terminal());
        assert!(Phase::Failed.terminal());
    }

    #[test]
    fn phase_switch_is_exhaustive() {
        fn classify(phase: Phase) -> &'static str {
            match phase {
                Phase::Prepared => "prepared",
                Phase::Activating => "activating",
                Phase::Healthy => "healthy",
                Phase::RollingBack => "rolling_back",
                Phase::RolledBack => "rolled_back",
                Phase::Committed => "committed",
                Phase::Failed => "failed",
            }
        }
        assert_eq!(classify(Phase::Prepared), "prepared");
        assert_eq!(classify(Phase::Failed), "failed");
    }

    #[test]
    fn main_abi_accepts_u16_and_two_slot_sockmap() {
        validate_abi(&expected_open_ports_abi(), &expected_open_ports_abi()).unwrap();
        validate_abi(&expected_redir_socket_abi(), &expected_redir_socket_abi()).unwrap();
        assert_eq!(expected_map_names(), ["open_ports", "redir_socket"]);
    }

    #[test]
    fn dest_key_20_byte_abi_is_rejected() {
        let live = expected_open_ports_abi();
        let candidate = MapAbi {
            key_size: 20,
            value_size: 4,
            ..live.clone()
        };
        let err = validate_abi(&candidate, &live).unwrap_err().to_string();
        assert!(err.contains("incompatible map ABI"));
        assert!(err.contains("not #37"));
    }

    #[test]
    fn extra_max_entries_is_rejected() {
        let live = expected_redir_socket_abi();
        let candidate = MapAbi {
            max_entries: 64,
            ..live.clone()
        };
        assert!(validate_abi(&candidate, &live).is_err());
    }

    #[test]
    fn journal_roundtrip_is_atomic_file_contract() {
        let dir = std::env::temp_dir().join(format!("waf-upgrade-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("journal.json");
        let journal = sample_journal(Phase::Prepared);
        write_journal_at(&path, &journal).unwrap();
        assert_eq!(read_journal_at(&path).unwrap(), Some(journal));
        assert!(!path.with_extension("json.tmp").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn journal_path_is_under_run_not_bpffs() {
        let p = journal_path(Path::new("/sys/fs/bpf/waf-sklookup"));
        assert!(p.starts_with("/run/waf-sklookup/upgrades/"));
        assert!(p.extension().is_some_and(|e| e == "json"));
        assert!(!p.starts_with("/sys/fs/bpf"));
    }

    #[test]
    fn missing_candidate_error_mentions_path() {
        let err = load_candidate(
            Path::new("/tmp/waf-sklookup-no-such-candidate.bpf.o"),
            Path::new("/tmp/waf-sklookup-no-such-pin"),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("does not exist"));
    }
}
