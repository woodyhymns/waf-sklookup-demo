//! Pin directory, map-size contracts, and program identity.
//!
//! Hardening notes:
//!  * `redir_socket` is sharded per worker (`SHARD_STRIDE` slots per protocol
//!    group), so `REDIR_MAX_ENTRIES` is no longer 2.
//!  * The program and its netns link are pinned alongside the maps, so a
//!    `ctl` process can verify it is talking to the program it expects.
//!  * `assert_program_identity` compares the loaded program tag against the
//!    tag recorded at pin time, which is what stops a new loader from writing
//!    a new key layout into an old program's map.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use libbpf_rs::MapCore;

use crate::load::LoadedBpf;

pub const DEFAULT_PIN_DIR: &str = "/sys/fs/bpf/waf-sklookup";
pub const OPEN_PORTS_MAP: &str = "open_ports";
pub const REDIR_SOCKET_MAP: &str = "redir_socket";
pub const STATS_MAP: &str = "stats";
pub const ANOMALIES_MAP: &str = "anomalies";
pub const ANOMALY_GATE_MAP: &str = "anomaly_gate";
pub const PROG_PIN: &str = "prog";
pub const LINK_PIN: &str = "link";
pub const IDENTITY_FILE: &str = "identity.json";
/// bpffs stores BPF objects, not arbitrary files; identity JSON must therefore
/// live on a normal filesystem. Kept under /run because it is runtime state and
/// must never survive a reboot without the pinned objects it describes.
const IDENTITY_SIDECAR_DIR: &str = "/run/waf-sklookup/identities";

/// Must match `dispatch.bpf.c` `open_ports` `max_entries`.
pub const OPEN_PORTS_MAX_ENTRIES: u32 = 131072;
pub const DEFAULT_BULK_BATCH: usize = 4096;

/// Must match `SHARD_STRIDE` / `REDIR_GROUPS` in `dispatch.bpf.c`.
pub const SHARD_STRIDE: u32 = 64;
pub const REDIR_GROUPS: u32 = 2;
pub const REDIR_MAX_ENTRIES: u32 = SHARD_STRIDE * REDIR_GROUPS;

/// Protocol groups (were "slots" when the sockmap had exactly two entries).
pub const REDIR_PRIMARY: u32 = 0;
pub const REDIR_TLS: u32 = 1;

/// Number of metric slots; must match `STAT__MAX` in `dispatch.bpf.c`.
pub const STATS_SLOTS: u32 = 16;

/// Sockmap index for a given protocol group and worker shard.
pub fn shard_slot(group: u32, shard: u32) -> Result<u32> {
    if group >= REDIR_GROUPS {
        bail!(
            "redir group {group} out of range (max {})",
            REDIR_GROUPS - 1
        );
    }
    if shard >= SHARD_STRIDE {
        bail!(
            "worker shard {shard} out of range (max {})",
            SHARD_STRIDE - 1
        );
    }
    Ok(group * SHARD_STRIDE + shard)
}

pub fn open_ports_path(pin_dir: impl AsRef<Path>) -> PathBuf {
    pin_dir.as_ref().join(OPEN_PORTS_MAP)
}

pub fn redir_socket_path(pin_dir: impl AsRef<Path>) -> PathBuf {
    pin_dir.as_ref().join(REDIR_SOCKET_MAP)
}

pub fn stats_path(pin_dir: impl AsRef<Path>) -> PathBuf {
    pin_dir.as_ref().join(STATS_MAP)
}

pub fn anomalies_path(pin_dir: impl AsRef<Path>) -> PathBuf {
    pin_dir.as_ref().join(ANOMALIES_MAP)
}

pub fn anomaly_gate_path(pin_dir: impl AsRef<Path>) -> PathBuf {
    pin_dir.as_ref().join(ANOMALY_GATE_MAP)
}

pub fn prog_path(pin_dir: impl AsRef<Path>) -> PathBuf {
    pin_dir.as_ref().join(PROG_PIN)
}

pub fn link_path(pin_dir: impl AsRef<Path>) -> PathBuf {
    pin_dir.as_ref().join(LINK_PIN)
}

/// Linux `BPF_FS_MAGIC` from `include/uapi/linux/magic.h`.
const BPF_FS_MAGIC: libc::c_long = 0xcafe_4a11;

/// Use the mount type rather than a `/sys/fs/bpf` pathname convention. CI and
/// production recovery tools regularly use private bpffs mounts below `/run`,
/// `/tmp`, or an isolated mount namespace; bpffs accepts pinned BPF objects but
/// rejects a normal JSON identity sidecar with EPERM.
fn is_bpffs(path: &Path) -> bool {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let mut probe = path;
    while !probe.exists() {
        let Some(parent) = probe.parent() else {
            return false;
        };
        probe = parent;
    }
    let Ok(c_path) = CString::new(probe.as_os_str().as_bytes()) else {
        return false;
    };
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    let rc = unsafe { libc::statfs(c_path.as_ptr(), stat.as_mut_ptr()) };
    rc == 0 && unsafe { stat.assume_init().f_type } == BPF_FS_MAGIC
}

fn identity_path_for_filesystem(pin_dir: &Path, bpffs: bool) -> PathBuf {
    if bpffs {
        PathBuf::from(IDENTITY_SIDECAR_DIR).join(format!(
            "{}-{}.json",
            pin_dir
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("waf-sklookup"),
            fnv1a64(pin_dir.as_os_str().as_encoded_bytes())
        ))
    } else {
        pin_dir.join(IDENTITY_FILE)
    }
}

pub fn identity_path(pin_dir: impl AsRef<Path>) -> PathBuf {
    let pin_dir = pin_dir.as_ref();
    identity_path_for_filesystem(pin_dir, is_bpffs(pin_dir))
}

/// Stable, dependency-free filename discriminator. The pin directory string
/// itself is also written inside the identity JSON-free sidecar's path; a hash
/// avoids unsafe slash escaping and makes multiple isolated test pin dirs work.
fn fnv1a64(bytes: &[u8]) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

fn all_pins(dir: &Path) -> Vec<PathBuf> {
    vec![
        open_ports_path(dir),
        redir_socket_path(dir),
        stats_path(dir),
        anomalies_path(dir),
        anomaly_gate_path(dir),
        prog_path(dir),
        link_path(dir),
    ]
}

/// Pin every map the dataplane exposes. Stale pins are unlinked first.
///
/// The observability maps (`stats`, `anomalies`, `anomaly_gate`) are pinned so
/// a separate read-only exporter can open them without loading the program.
pub fn pin_maps(dir: &Path, bpf: &mut LoadedBpf<'_>) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("mkdir {}", dir.display()))?;
    // Do not leave an identity record that describes pins we are about to
    // replace (and bpffs cannot hold it in the first place).
    let _ = fs::remove_file(identity_path(dir));
    for path in all_pins(dir) {
        let _ = fs::remove_file(path);
    }

    let wanted = [
        (OPEN_PORTS_MAP, open_ports_path(dir)),
        (REDIR_SOCKET_MAP, redir_socket_path(dir)),
        (STATS_MAP, stats_path(dir)),
        (ANOMALIES_MAP, anomalies_path(dir)),
        (ANOMALY_GATE_MAP, anomaly_gate_path(dir)),
    ];

    let result = (|| -> Result<()> {
        for (name, path) in &wanted {
            bpf.pin_map(name, path)
                .with_context(|| format!("pin {}", path.display()))?;
        }
        Ok(())
    })();

    if result.is_err() {
        for path in all_pins(dir) {
            let _ = fs::remove_file(path);
        }
        let _ = fs::remove_file(identity_path(dir));
    }
    result
}

/// Pin all BPF objects required by a second-process control plane.
///
/// The old code only pinned maps while `identity::assert_pinned_program_matches`
/// tried to open `prog`, which did not exist. Pinning the dispatch program and
/// its netns link makes the program tag a real runtime contract rather than an
/// untested intent. Any failure rolls back every object to avoid a half-pinned
/// dataplane that looks healthy to `ctl`.
pub fn pin_all(dir: &Path, bpf: &mut LoadedBpf<'_>, link: &mut libbpf_rs::Link) -> Result<()> {
    pin_maps(dir, bpf)?;
    let result = (|| -> Result<()> {
        bpf.pin_program(&prog_path(dir))
            .with_context(|| format!("pin dispatch program {}", prog_path(dir).display()))?;
        link.pin(link_path(dir))
            .with_context(|| format!("pin netns link {}", link_path(dir).display()))?;
        Ok(())
    })();
    if result.is_err() {
        unpin_maps(dir);
    }
    result
}

pub fn unpin_maps(dir: &Path) {
    for path in all_pins(dir) {
        let _ = fs::remove_file(path);
    }
    let _ = fs::remove_file(identity_path(dir));
    let _ = fs::remove_dir(dir);
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

/// Guard against a new loader mutating an old program's maps. The key layout
/// changed with the hardening work, so a size mismatch means the running
/// dataplane predates this binary and must be reloaded, not written to.
pub fn assert_open_ports_layout(map: &impl MapCore) -> Result<()> {
    assert_open_ports_max_entries(map)?;
    let key = map.key_size();
    let value = map.value_size();
    if key as usize != crate::key::PORT_KEY_SIZE || value as usize != crate::key::PORT_VAL_SIZE {
        anyhow::bail!(
            "open_ports layout key={key} value={value}, want key={} value={}: \
             the loaded BPF program predates the (family, addr, port) key. \
             Restart the loader to reload the dataplane before mutating state.",
            crate::key::PORT_KEY_SIZE,
            crate::key::PORT_VAL_SIZE
        );
    }
    Ok(())
}

pub fn assert_redir_socket_layout(map: &impl MapCore) -> Result<()> {
    let got = map.max_entries();
    if got != REDIR_MAX_ENTRIES {
        anyhow::bail!(
            "redir_socket max_entries={got} want {REDIR_MAX_ENTRIES} \
             (loaded program has no worker shards; restart the loader)"
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
    fn redir_groups() {
        assert_eq!(REDIR_PRIMARY, 0);
        assert_eq!(REDIR_TLS, 1);
        assert_eq!(REDIR_MAX_ENTRIES, 128);
    }

    #[test]
    fn shard_slots_are_grouped_by_stride() {
        assert_eq!(shard_slot(0, 0).unwrap(), 0);
        assert_eq!(shard_slot(0, 63).unwrap(), 63);
        assert_eq!(shard_slot(1, 0).unwrap(), 64);
        assert_eq!(shard_slot(1, 63).unwrap(), 127);
        assert!(shard_slot(2, 0).is_err());
        assert!(shard_slot(0, 64).is_err());
    }

    #[test]
    fn all_pin_paths_include_program_and_link() {
        let pins = all_pins(Path::new("/sys/fs/bpf/waf-test"));
        assert!(pins.contains(&PathBuf::from("/sys/fs/bpf/waf-test/prog")));
        assert!(pins.contains(&PathBuf::from("/sys/fs/bpf/waf-test/link")));
    }

    #[test]
    fn bpffs_identity_uses_run_sidecar_not_a_regular_bpffs_file() {
        // Unit tests do not require /sys/fs/bpf to be mounted in the host
        // sandbox; the real-kernel E2E covers statfs() against an actual mount.
        let p = identity_path_for_filesystem(Path::new("/sys/fs/bpf/waf-e2e"), true);
        assert!(
            p.starts_with("/run/waf-sklookup/identities"),
            "{}",
            p.display()
        );
        assert!(p
            .file_name()
            .unwrap()
            .to_string_lossy()
            .contains("waf-e2e-"));
    }

    // Regression: a private bpffs mount may be under /tmp or another runtime
    // path. Prefix-only detection writes identity.json into bpffs and later
    // ctl fails with EPERM. The filesystem type, not pathname, decides.
    #[test]
    fn private_bpffs_mount_uses_runtime_sidecar() {
        let p = identity_path_for_filesystem(Path::new("/tmp/private-bpffs/pin"), true);
        assert!(
            p.starts_with("/run/waf-sklookup/identities"),
            "{}",
            p.display()
        );
        assert!(!p.to_string_lossy().contains("identity.json"));
    }

    #[test]
    fn non_bpffs_identity_stays_with_test_pin_dir() {
        let p = identity_path("/tmp/waf-test-pins");
        assert_eq!(p, PathBuf::from("/tmp/waf-test-pins/identity.json"));
    }

    #[test]
    fn open_ports_max_entries_constant() {
        assert!(OPEN_PORTS_MAX_ENTRIES >= 65536);
        assert_eq!(OPEN_PORTS_MAX_ENTRIES, 131072);
    }

    #[test]
    fn dispatch_c_constants_match() {
        let src = include_str!("../../../dispatch.bpf.c");
        assert!(
            src.contains("max_entries, 131072"),
            "dispatch.bpf.c must keep open_ports max_entries 131072"
        );
        assert!(
            src.contains("#define SHARD_STRIDE 64"),
            "dispatch.bpf.c SHARD_STRIDE must match pin.rs"
        );
        assert!(
            src.contains("#define REDIR_GROUPS 2"),
            "dispatch.bpf.c REDIR_GROUPS must match pin.rs"
        );
        assert!(
            src.contains("BPF_SK_LOOKUP_F_NO_REUSEPORT"),
            "dispatch.bpf.c must pass NO_REUSEPORT so shard choice is authoritative"
        );
    }
}
