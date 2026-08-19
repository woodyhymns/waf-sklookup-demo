//! Persistent single-machine mutation gate.

use std::fs::{self, OpenOptions};
use std::path::Path;

use anyhow::{bail, Context, Result};

pub const DEFAULT_FREEZE_FILE: &str = "/run/waf-sklookup/frozen";

pub fn is_frozen(path: &Path) -> bool {
    path.exists()
}

pub fn set_frozen(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("create freeze directory {}", parent.display()))?;
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .with_context(|| format!("set freeze state {}", path.display()))?;
    Ok(())
}

pub fn clear_frozen(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("clear freeze state {}", path.display())),
    }
}

pub fn reject_if_frozen(
    path: &Path,
    op: &str,
    tenant: &str,
    site: &str,
    ports: &[u16],
) -> Result<()> {
    if is_frozen(path) {
        let ports = match ports {
            [] => "none".to_string(),
            [p] => p.to_string(),
            ps if ps.len() <= 16 => ps.iter().map(u16::to_string).collect::<Vec<_>>().join(","),
            ps => format!("count={}", ps.len()),
        };
        bail!("machine is frozen; refusing {op} tenant={tenant} site={site} ports={ports}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn freeze_rejects_mutations_and_unfreeze_allows_again() {
        let path = std::env::temp_dir().join(format!("waf-freeze-test-{}", std::process::id()));
        let _ = clear_frozen(&path);
        for op in ["add", "open", "bulk", "fill", "apply-central"] {
            assert!(reject_if_frozen(&path, op, "demo", "local", &[18081]).is_ok());
        }
        set_frozen(&path).unwrap();
        assert!(is_frozen(&path));
        for op in ["add", "open", "bulk", "fill", "apply-central"] {
            let err = reject_if_frozen(&path, op, "demo", "local", &[18081])
                .unwrap_err()
                .to_string();
            assert!(err.contains("machine is frozen"));
        }
        clear_frozen(&path).unwrap();
        assert!(!is_frozen(&path));
        assert!(reject_if_frozen(&path, "add", "demo", "local", &[18081]).is_ok());
    }
}
