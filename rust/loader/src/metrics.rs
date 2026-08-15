use std::fs;
use std::path::Path;

pub const DEFAULT_METRICS_FILE: &str = "/run/waf-sklookup/apply_fail_total";
pub const DEFAULT_APPLY_STAMP: &str = "/run/waf-sklookup/last-apply-central";

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
