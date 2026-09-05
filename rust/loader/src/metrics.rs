use std::fs;
use std::path::Path;

use crate::pin::OPEN_PORTS_MAX_ENTRIES;

pub const DEFAULT_METRICS_FILE: &str = "/run/waf-sklookup/apply_fail_total";
pub const DEFAULT_APPLY_STAMP: &str = "/run/waf-sklookup/last-apply-central";

/// One sampling of `open_ports` occupancy. Pressure is visibility only;
/// admission uses integer `desired.len() <= capacity`, not this ratio.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CapacitySnapshot {
    pub entries: u32,
    pub max_entries: u32,
    pub headroom_entries: u32,
    pub pressure_ratio: f64,
}

pub fn capacity_snapshot(entries: usize) -> CapacitySnapshot {
    let max_entries = OPEN_PORTS_MAX_ENTRIES;
    let entries = u32::try_from(entries).unwrap_or(u32::MAX).min(max_entries);
    CapacitySnapshot {
        entries,
        max_entries,
        headroom_entries: max_entries.saturating_sub(entries),
        pressure_ratio: f64::from(entries) / f64::from(max_entries),
    }
}

pub fn read(path: &Path) -> u64 {
    fs::read_to_string(path).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0)
}

pub fn increment(path: &Path) {
    let next = read(path).saturating_add(1);
    if let Some(parent) = path.parent() { let _ = fs::create_dir_all(parent); }
    let _ = fs::write(path, format!("{next}\n"));
}

pub fn rfc3339_now() -> String {
    let mut t: libc::time_t = 0;
    unsafe { libc::time(&mut t) };
    let mut tm = std::mem::MaybeUninit::<libc::tm>::uninit();
    unsafe { libc::gmtime_r(&t, tm.as_mut_ptr()) };
    let tm = unsafe { tm.assume_init() };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec
    )
}

pub fn write_apply_stamp(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() { fs::create_dir_all(parent)?; }
    fs::write(path, format!("{}\n", rfc3339_now()))
}

pub fn read_apply_stamp(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_snapshot_empty_and_60k() {
        let empty = capacity_snapshot(0);
        assert_eq!(empty.entries, 0);
        assert_eq!(empty.max_entries, OPEN_PORTS_MAX_ENTRIES);
        assert_eq!(empty.headroom_entries, OPEN_PORTS_MAX_ENTRIES);
        assert_eq!(empty.pressure_ratio, 0.0);

        let mid = capacity_snapshot(60_000);
        assert_eq!(mid.entries, 60_000);
        assert_eq!(mid.headroom_entries, OPEN_PORTS_MAX_ENTRIES - 60_000);
        assert!((mid.pressure_ratio - (60_000.0 / f64::from(OPEN_PORTS_MAX_ENTRIES))).abs() < 1e-12);
    }

    #[test]
    fn capacity_snapshot_clamps_to_max() {
        let over = capacity_snapshot(OPEN_PORTS_MAX_ENTRIES as usize + 10);
        assert_eq!(over.entries, OPEN_PORTS_MAX_ENTRIES);
        assert_eq!(over.headroom_entries, 0);
        assert_eq!(over.pressure_ratio, 1.0);
    }
}
