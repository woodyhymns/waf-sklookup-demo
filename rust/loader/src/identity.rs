//! Program identity: kernel prog id plus instruction tag.
//!
//! Why this exists: the loader binary is upgraded independently of the BPF
//! program that is already attached in the kernel. Without an identity check a
//! new `ctl` can happily write a new key layout into an old program's map, and
//! the failure shows up later as "some ports are unreachable" with no logs.
//!
//! The tag is a truncated hash of the program's instructions, exposed by the
//! kernel via `BPF_OBJ_GET_INFO_BY_FD`. It changes whenever the dataplane logic
//! changes, which is exactly the signal we want.

use std::fs;
use std::path::Path;

use std::os::fd::AsRawFd;

use anyhow::{bail, Context, Result};
use libbpf_rs::Program;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramIdentity {
    /// Kernel-assigned program id (changes on every load).
    pub id: u32,
    /// Instruction tag, hex encoded (stable for identical program text).
    pub tag: String,
    /// Key/value sizes of `open_ports`, so a layout change is also visible.
    #[serde(default)]
    pub open_ports_key_size: u32,
    #[serde(default)]
    pub open_ports_value_size: u32,
}

/// `struct bpf_prog_info` prefix, up to and including `tag`.
#[repr(C)]
#[derive(Default)]
struct ProgInfoPrefix {
    prog_type: u32,
    id: u32,
    tag: [u8; 8],
    jited_prog_len: u32,
    xlated_prog_len: u32,
    jited_prog_insns: u64,
    xlated_prog_insns: u64,
    load_time: u64,
    created_by_uid: u32,
    nr_map_ids: u32,
    map_ids: u64,
    name: [u8; 16],
}

pub fn from_prog_fd(fd: i32) -> Result<ProgramIdentity> {
    // bpf(BPF_OBJ_GET_INFO_BY_FD, ...)
    #[repr(C)]
    struct InfoAttr {
        bpf_fd: u32,
        info_len: u32,
        info: u64,
    }
    const BPF_OBJ_GET_INFO_BY_FD: i32 = 15;

    let mut info = ProgInfoPrefix::default();
    // The kernel writes at most info_len bytes; a short buffer is fine because
    // everything we need lives in the prefix.
    let mut attr = InfoAttr {
        bpf_fd: fd as u32,
        info_len: std::mem::size_of::<ProgInfoPrefix>() as u32,
        info: &mut info as *mut _ as u64,
    };
    let rc = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_OBJ_GET_INFO_BY_FD,
            &mut attr as *mut _ as *mut libc::c_void,
            std::mem::size_of::<InfoAttr>() as u32,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error()).context("BPF_OBJ_GET_INFO_BY_FD");
    }
    Ok(ProgramIdentity {
        id: info.id,
        tag: hex(&info.tag),
        open_ports_key_size: crate::key::PORT_KEY_SIZE as u32,
        open_ports_value_size: crate::key::PORT_VAL_SIZE as u32,
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn write(pin_dir: &Path, id: &ProgramIdentity) -> Result<()> {
    let path = crate::pin::identity_path(pin_dir);
    let parent = path
        .parent()
        .context("identity sidecar path has no parent directory")?;
    // bpffs accepts pinned BPF objects only (not JSON files). The production
    // path therefore lives under /run; ensure it exists with non-world-writable
    // permissions before atomically replacing the record.
    fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
    let json = serde_json::to_string(id).context("serialize program identity")?;
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, format!("{json}\n")).with_context(|| format!("write {}", tmp.display()))?;
    fs::rename(&tmp, &path).with_context(|| format!("replace {}", path.display()))?;
    Ok(())
}

pub fn read(pin_dir: &Path) -> Result<Option<ProgramIdentity>> {
    let path = crate::pin::identity_path(pin_dir);
    match fs::read_to_string(&path) {
        Ok(raw) => Ok(Some(
            serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))?,
        )),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("read {}", path.display())),
    }
}

/// Refuse to mutate state when the recorded key layout differs from ours.
///
/// A missing identity file is tolerated (older deployments, or a pin directory
/// created before this feature) but reported by callers so operators can see
/// the gap in `status`.
pub fn assert_compatible(pin_dir: &Path) -> Result<Option<ProgramIdentity>> {
    let Some(recorded) = read(pin_dir)? else {
        return Ok(None);
    };
    if recorded.open_ports_key_size != crate::key::PORT_KEY_SIZE as u32
        || recorded.open_ports_value_size != crate::key::PORT_VAL_SIZE as u32
    {
        bail!(
            "pinned dataplane was loaded with open_ports key={} value={} but this binary uses key={} value={}: \
             restart the loader to reload the dataplane before mutating state (prog id={} tag={})",
            recorded.open_ports_key_size,
            recorded.open_ports_value_size,
            crate::key::PORT_KEY_SIZE,
            crate::key::PORT_VAL_SIZE,
            recorded.id,
            recorded.tag
        );
    }
    Ok(Some(recorded))
}

/// Verify that the sidecar identity describes the program actually pinned in
/// bpffs. Layout-only checks catch most upgrade mistakes, but an old program
/// can coincidentally have identical map sizes; comparing the kernel tag closes
/// that hole. Missing sidecars are deliberately tolerated to support in-place
/// upgrade from pre-hardening deployments, but a present sidecar is a contract
/// and must match exactly.
pub fn assert_pinned_program_matches(pin_dir: &Path) -> Result<Option<ProgramIdentity>> {
    let Some(recorded) = assert_compatible(pin_dir)? else {
        return Ok(None);
    };
    let path = crate::pin::prog_path(pin_dir);
    let fd = Program::fd_from_pinned_path(&path)
        .with_context(|| format!("open pinned program {}", path.display()))?;
    let live = from_prog_fd(fd.as_raw_fd())?;
    if live.tag != recorded.tag {
        bail!(
            "pinned program tag mismatch: sidecar={} live={} (sidecar prog id={}, live id={}); \
             refuse to mutate maps until the loader is restarted",
            recorded.tag,
            live.tag,
            recorded.id,
            live.id
        );
    }
    Ok(Some(live))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encodes_lowercase_fixed_width() {
        assert_eq!(hex(&[0x00, 0x0f, 0xff]), "000fff");
    }

    #[test]
    fn identity_roundtrips_through_pin_dir() {
        let dir = std::env::temp_dir().join(format!("waf-identity-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let id = ProgramIdentity {
            id: 42,
            tag: "deadbeefdeadbeef".into(),
            open_ports_key_size: crate::key::PORT_KEY_SIZE as u32,
            open_ports_value_size: crate::key::PORT_VAL_SIZE as u32,
        };
        write(&dir, &id).unwrap();
        assert_eq!(read(&dir).unwrap().unwrap(), id);
        assert_eq!(assert_compatible(&dir).unwrap().unwrap(), id);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn tag_is_the_compatibility_boundary_not_the_volatile_program_id() {
        let sidecar = ProgramIdentity {
            id: 1,
            tag: "aaaaaaaaaaaaaaaa".into(),
            open_ports_key_size: crate::key::PORT_KEY_SIZE as u32,
            open_ports_value_size: crate::key::PORT_VAL_SIZE as u32,
        };
        let same_code_reloaded = ProgramIdentity {
            id: 2,
            ..sidecar.clone()
        };
        assert_eq!(sidecar.tag, same_code_reloaded.tag);
        assert_ne!(sidecar.id, same_code_reloaded.id);
    }

    #[test]
    fn stale_layout_is_refused() {
        let dir = std::env::temp_dir().join(format!("waf-identity-stale-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        // 2-byte key = the pre-hardening port-only layout.
        let old = ProgramIdentity {
            id: 7,
            tag: "0011223344556677".into(),
            open_ports_key_size: 2,
            open_ports_value_size: 1,
        };
        write(&dir, &old).unwrap();
        let err = assert_compatible(&dir).unwrap_err().to_string();
        assert!(err.contains("restart the loader"), "{err}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_identity_is_tolerated() {
        let dir = std::env::temp_dir().join(format!("waf-identity-none-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        assert!(assert_compatible(&dir).unwrap().is_none());
        let _ = fs::remove_dir_all(&dir);
    }
}
