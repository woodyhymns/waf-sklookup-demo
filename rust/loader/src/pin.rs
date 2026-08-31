//! Pin directory and map-size contracts (must match Go `loader.go` / `ports_bulk.go`).

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use libbpf_rs::{Link, MapCore};

use crate::load::LoadedBpf;

pub const DEFAULT_PIN_DIR: &str = "/sys/fs/bpf/waf-sklookup";
pub const OPEN_PORTS_MAP: &str = "open_ports";
pub const REDIR_SOCKET_MAP: &str = "redir_socket";
pub const SK_LOOKUP_LINK: &str = "sk_lookup";

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

pub fn sk_lookup_link_path(pin_dir: impl AsRef<Path>) -> PathBuf {
    pin_dir.as_ref().join(SK_LOOKUP_LINK)
}

pub fn maps_pinned(dir: &Path) -> bool {
    open_ports_path(dir).exists() && redir_socket_path(dir).exists()
}

pub fn link_pinned(dir: &Path) -> bool {
    sk_lookup_link_path(dir).exists()
}

pub fn dataplane_pinned(dir: &Path) -> bool {
    maps_pinned(dir) && link_pinned(dir)
}

/// Reuse pinned maps before load when present; pin any map not yet on bpffs after load.
pub fn ensure_maps_pinned(dir: &Path, bpf: &mut LoadedBpf<'_>) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("mkdir {}", dir.display()))?;
    match bpf {
        LoadedBpf::C(skel) => {
            if !open_ports_path(dir).exists() {
                skel.maps
                    .open_ports
                    .pin(open_ports_path(dir))
                    .with_context(|| format!("pin {}", open_ports_path(dir).display()))?;
            }
            if !redir_socket_path(dir).exists() {
                skel.maps.redir_socket.pin(redir_socket_path(dir)).with_context(|| {
                    format!("pin {}", redir_socket_path(dir).display())
                })?;
            }
        }
        LoadedBpf::Rust(obj) => {
            if !open_ports_path(dir).exists() {
                let mut open_ports = obj
                    .maps_mut()
                    .find(|m| m.name() == OPEN_PORTS_MAP)
                    .context("Rust BPF object missing map open_ports")?;
                open_ports
                    .pin(open_ports_path(dir))
                    .with_context(|| format!("pin {}", open_ports_path(dir).display()))?;
            }
            if !redir_socket_path(dir).exists() {
                let mut redir_socket = obj
                    .maps_mut()
                    .find(|m| m.name() == REDIR_SOCKET_MAP)
                    .context("Rust BPF object missing map redir_socket")?;
                redir_socket.pin(redir_socket_path(dir)).with_context(|| {
                    format!("pin {}", redir_socket_path(dir).display())
                })?;
            }
        }
    }
    Ok(())
}

/// Install teardown: detach pinned sk_lookup link and remove bpffs pins.
pub fn unpin_dataplane(dir: &Path) -> Result<()> {
    let link_path = sk_lookup_link_path(dir);
    if link_path.exists() {
        if let Ok(mut link) = Link::open(&link_path) {
            let _ = link.detach();
            let _ = link.unpin();
        }
        let _ = fs::remove_file(&link_path);
    }
    let _ = fs::remove_file(open_ports_path(dir));
    let _ = fs::remove_file(redir_socket_path(dir));
    let _ = fs::remove_dir(dir);
    Ok(())
}

pub fn assert_open_ports_max_entries(map: &impl MapCore) -> Result<()> {
    let got = map.max_entries();
    if got != OPEN_PORTS_MAX_ENTRIES {
        anyhow::bail!(
            "open_ports max_entries={got} want {OPEN_PORTS_MAX_ENTRIES} (rebuild the selected BPF object)"
        );
    }
    Ok(())
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

    #[test]
    fn sk_lookup_link_path_under_default_pin_dir() {
        let p = sk_lookup_link_path(DEFAULT_PIN_DIR);
        assert_eq!(p, PathBuf::from("/sys/fs/bpf/waf-sklookup/sk_lookup"));
    }

    #[test]
    fn dataplane_pinned_requires_maps_and_link() {
        let dir = std::env::temp_dir().join(format!("waf-pin-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        assert!(!dataplane_pinned(&dir));
        fs::write(open_ports_path(&dir), b"x").unwrap();
        assert!(!dataplane_pinned(&dir));
        fs::write(redir_socket_path(&dir), b"x").unwrap();
        assert!(!dataplane_pinned(&dir));
        fs::write(sk_lookup_link_path(&dir), b"x").unwrap();
        assert!(dataplane_pinned(&dir));
        let _ = fs::remove_dir_all(&dir);
    }
}
