use std::fs;
use std::path::Path;

pub const DEFAULT_METRICS_FILE: &str = "/run/waf-sklookup/apply_fail_total";

pub fn read(path: &Path) -> u64 {
    fs::read_to_string(path).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0)
}

pub fn increment(path: &Path) {
    let next = read(path).saturating_add(1);
    if let Some(parent) = path.parent() { let _ = fs::create_dir_all(parent); }
    let _ = fs::write(path, format!("{next}\n"));
}
