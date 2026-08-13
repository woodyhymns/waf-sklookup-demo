//! Pin directory and map-size contracts (must match Go `loader.go` / `ports_bulk.go`).

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use libbpf_rs::MapCore;

use crate::dispatch::DispatchSkel;

pub const DEFAULT_PIN_DIR: &str = "/sys/fs/bpf/waf-sklookup";
pub const OPEN_PORTS_MAP: &str = "open_ports";
pub const REDIR_SOCKET_MAP: &str = "redir_socket";

/// Must match `dispatch.bpf.c` `open_ports` `max_entries`.
pub const OPEN_PORTS_MAX_ENTRIES: u32 = 131072;
pub const DEFAULT_BULK_BATCH: usize = 4096;

pub const REDIR_PRIMARY: u32 = 0;
pub const REDIR_TLS: u32 = 1;

pub fn open_ports_path(pin_dir: impl AsRef<Path>) -> PathBuf {
    pin_dir.as_ref().join(OPEN_PORTS_MAP)
}

pub fn redir_socket_path(pin_dir: impl AsRef<Path>) -> PathBuf {
    pin_dir.as_ref().join(REDIR_SOCKET_MAP)
}

/// Pin `open_ports` + `redir_socket`. Unlink stale pins first (same as Go).
pub fn pin_maps(dir: &Path, skel: &mut DispatchSkel<'_>) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("mkdir {}", dir.display()))?;
    let _ = fs::remove_file(open_ports_path(dir));
    let _ = fs::remove_file(redir_socket_path(dir));
    skel.maps
        .open_ports
        .pin(open_ports_path(dir))
        .with_context(|| format!("pin {}", open_ports_path(dir).display()))?;
    if let Err(err) = skel.maps.redir_socket.pin(redir_socket_path(dir)) {
        let _ = skel.maps.open_ports.unpin(open_ports_path(dir));
        return Err(err).with_context(|| format!("pin {}", redir_socket_path(dir).display()));
    }
    Ok(())
}

pub fn unpin_maps(dir: &Path) {
    let _ = fs::remove_file(open_ports_path(dir));
    let _ = fs::remove_file(redir_socket_path(dir));
    let _ = fs::remove_dir(dir);
}

pub fn assert_open_ports_max_entries(map: &impl MapCore) -> Result<()> {
    let got = map.max_entries();
    if got != OPEN_PORTS_MAX_ENTRIES {
        anyhow::bail!(
            "open_ports max_entries={got} want {OPEN_PORTS_MAX_ENTRIES} (rebuild from dispatch.bpf.c)"
        );
    }
    Ok(())
}

pub struct UnpinOnDrop(pub Option<PathBuf>);

impl Drop for UnpinOnDrop {
    fn drop(&mut self) {
        if let Some(dir) = self.0.take() {
            unpin_maps(&dir);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redir_slots() {
        assert_eq!(REDIR_PRIMARY, 0);
        assert_eq!(REDIR_TLS, 1);
    }

    #[test]
    fn open_ports_max_entries_constant() {
        assert!(OPEN_PORTS_MAX_ENTRIES >= 65536);
        assert!(OPEN_PORTS_MAX_ENTRIES >= 60000);
        assert_eq!(OPEN_PORTS_MAX_ENTRIES, 131072);
    }

    #[test]
    fn dispatch_c_max_entries_matches_constant() {
        let src = include_str!("../../../dispatch.bpf.c");
        assert!(
            src.contains("max_entries, 131072"),
            "dispatch.bpf.c must keep open_ports max_entries 131072"
        );
    }
}
