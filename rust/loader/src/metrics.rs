//! Metrics: control-plane counters plus the dataplane `stats` map.
//!
//! Before hardening this module only maintained two files (`apply_fail_total`,
//! `last-apply-central`), so a production "port unreachable" report could not
//! be attributed to any component. The dataplane now counts every terminal
//! path and classifies `bpf_sk_assign()` failures by errno, and this module
//! reads those counters back out of the pinned per-CPU map.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use libbpf_rs::{MapCore, MapFlags};

pub const DEFAULT_METRICS_FILE: &str = "/run/waf-sklookup/apply_fail_total";
pub const DEFAULT_APPLY_STAMP: &str = "/run/waf-sklookup/last-apply-central";
pub const DEFAULT_REJECTION_FILE: &str = "/run/waf-sklookup/last_rejection_reason";

/// Immutable capacity view derived from one map-entry snapshot. Keeping these
/// fields together prevents operators from seeing an entries value from one
/// scrape and a pressure ratio calculated against another capacity contract.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CapacitySnapshot {
    pub entries: u64,
    pub capacity: u64,
    pub headroom: u64,
    pub pressure_ratio: f64,
}

impl CapacitySnapshot {
    /// Returns None for an impossible map state. Callers must expose an
    /// explicit exporter failure rather than underflowing headroom or claiming
    /// a plausible pressure ratio after a corrupt/incompatible read.
    pub fn new(entries: u64, capacity: u64) -> Option<Self> {
        if capacity == 0 || entries > capacity {
            return None;
        }
        Some(Self {
            entries,
            capacity,
            headroom: capacity - entries,
            pressure_ratio: entries as f64 / capacity as f64,
        })
    }
}

// ---------------------------------------------------------------------------
// Control-plane counters (unchanged file contract: still cheap to cat during
// an incident, and existing runbooks keep working).
// ---------------------------------------------------------------------------

pub fn read(path: &Path) -> u64 {
    fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

pub fn increment(path: &Path) {
    let next = read(path).saturating_add(1);
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(path, format!("{next}\n"));
}

/// Stable control-plane rejection vocabulary. Never persist raw error strings:
/// they can contain tenant names, paths, addresses, and unbounded input.
pub fn classify_rejection(error: &str) -> &'static str {
    let error = error.to_ascii_lowercase();
    if error.contains("reserved") {
        "reservation"
    } else if error.contains("denied") {
        "deny"
    } else if error.contains("quota") || error.contains("capacity") {
        "capacity"
    } else if error.contains("overlap") || error.contains("conflict") {
        "overlap"
    } else if error.contains("frozen") {
        "frozen"
    } else if error.contains("identity") || error.contains("manifest") {
        "identity"
    } else {
        "other"
    }
}

pub fn rejection_path(metrics_file: &Path) -> PathBuf {
    metrics_file
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("last_rejection_reason")
}

pub fn record_rejection(metrics_file: &Path, error: &str) {
    increment(metrics_file);
    let path = rejection_path(metrics_file);
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(path, format!("{}\n", classify_rejection(error)));
}

pub fn read_last_rejection(metrics_file: &Path) -> Option<String> {
    fs::read_to_string(rejection_path(metrics_file))
        .ok()
        .map(|raw| raw.trim().to_owned())
        .filter(|value| {
            matches!(
                value.as_str(),
                "reservation" | "deny" | "capacity" | "overlap" | "frozen" | "identity" | "other"
            )
        })
}

pub fn rfc3339_now() -> String {
    let mut t: libc::time_t = 0;
    unsafe { libc::time(&mut t) };
    let mut tm = std::mem::MaybeUninit::<libc::tm>::uninit();
    unsafe { libc::gmtime_r(&t, tm.as_mut_ptr()) };
    let tm = unsafe { tm.assume_init() };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}

pub fn write_apply_stamp(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, format!("{}\n", rfc3339_now()))
}

pub fn read_apply_stamp(path: &Path) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Unix seconds for an RFC3339 stamp we wrote ourselves. Used by the exporter
/// so alerting can express "last central apply is too old".
pub fn apply_stamp_unix(stamp: &str) -> Option<i64> {
    let s = stamp.trim();
    if s.len() < 19 {
        return None;
    }
    let num = |a: usize, b: usize| -> Option<i64> { s.get(a..b)?.parse().ok() };
    let year = num(0, 4)?;
    let month = num(5, 7)?;
    let day = num(8, 10)?;
    let hour = num(11, 13)?;
    let min = num(14, 16)?;
    let sec = num(17, 19)?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // days_from_civil (Howard Hinnant).
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 }.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(days * 86400 + hour * 3600 + min * 60 + sec)
}

// ---------------------------------------------------------------------------
// Dataplane counters
// ---------------------------------------------------------------------------

/// Dataplane metric slots. Must match `enum stat_slot` in `dispatch.bpf.c`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stat {
    AssignOk = 0,
    PortMiss = 1,
    NoSlot = 2,
    InvalidGroup = 3,
    ErrEexist = 4,
    ErrEafnosupport = 5,
    ErrEsocktnosupport = 6,
    ErrEprototype = 7,
    ErrOther = 8,
    PassNonTcp = 9,
    PassBadFamily = 10,
    ShardFallback = 11,
}

impl Stat {
    pub const ALL: [Stat; 12] = [
        Stat::AssignOk,
        Stat::PortMiss,
        Stat::NoSlot,
        Stat::InvalidGroup,
        Stat::ErrEexist,
        Stat::ErrEafnosupport,
        Stat::ErrEsocktnosupport,
        Stat::ErrEprototype,
        Stat::ErrOther,
        Stat::PassNonTcp,
        Stat::PassBadFamily,
        Stat::ShardFallback,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Stat::AssignOk => "assign_ok",
            Stat::PortMiss => "port_miss",
            Stat::NoSlot => "no_slot",
            Stat::InvalidGroup => "invalid_group",
            Stat::ErrEexist => "assign_err_eexist",
            Stat::ErrEafnosupport => "assign_err_eafnosupport",
            Stat::ErrEsocktnosupport => "assign_err_esocktnosupport",
            Stat::ErrEprototype => "assign_err_eprototype",
            Stat::ErrOther => "assign_err_other",
            Stat::PassNonTcp => "pass_non_tcp",
            Stat::PassBadFamily => "pass_bad_family",
            Stat::ShardFallback => "shard_fallback",
        }
    }

    /// One-line operational meaning, emitted as Prometheus HELP text.
    pub fn help(self) -> &'static str {
        match self {
            Stat::AssignOk => "SYNs successfully steered to a listen socket",
            Stat::PortMiss => "destination not steered; fell through to bind lookup",
            Stat::NoSlot => "no listen socket in the selected shard or its fallback",
            Stat::InvalidGroup => "open_ports value had an out-of-range group or shard count",
            Stat::ErrEexist => {
                "bpf_sk_assign -EEXIST: another sk_lookup program already selected a socket"
            }
            Stat::ErrEafnosupport => {
                "bpf_sk_assign -EAFNOSUPPORT: socket family incompatible with packet"
            }
            Stat::ErrEsocktnosupport => {
                "bpf_sk_assign -ESOCKTNOSUPPORT: socket not listening (stale worker fd)"
            }
            Stat::ErrEprototype => "bpf_sk_assign -EPROTOTYPE: L4 protocol mismatch",
            Stat::ErrOther => "bpf_sk_assign failed with another errno",
            Stat::PassNonTcp => "non-TCP traffic passed through untouched",
            Stat::PassBadFamily => "unsupported address family passed through untouched",
            Stat::ShardFallback => "selected shard was empty; served by shard 0 of the same group",
        }
    }

    /// True when a non-zero rate indicates a fault rather than normal traffic.
    pub fn is_fault(self) -> bool {
        matches!(
            self,
            Stat::NoSlot
                | Stat::InvalidGroup
                | Stat::ErrEexist
                | Stat::ErrEafnosupport
                | Stat::ErrEsocktnosupport
                | Stat::ErrEprototype
                | Stat::ErrOther
        )
    }
}

/// Snapshot of the dataplane counters, summed across CPUs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DataplaneStats {
    pub values: Vec<(&'static str, u64)>,
}

impl DataplaneStats {
    pub fn get(&self, name: &str) -> u64 {
        self.values
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| *v)
            .unwrap_or(0)
    }

    pub fn total_faults(&self) -> u64 {
        Stat::ALL
            .iter()
            .filter(|s| s.is_fault())
            .map(|s| self.get(s.name()))
            .sum()
    }

    /// Share of steering attempts that failed. None when idle.
    pub fn fault_ratio(&self) -> Option<f64> {
        let ok = self.get(Stat::AssignOk.name());
        let faults = self.total_faults();
        let total = ok + faults;
        if total == 0 {
            None
        } else {
            Some(faults as f64 / total as f64)
        }
    }
}

/// Sum a `BPF_MAP_TYPE_PERCPU_ARRAY` of u64 counters.
pub fn read_stats(map: &(impl MapCore + ?Sized)) -> Result<DataplaneStats> {
    let mut out = Vec::with_capacity(Stat::ALL.len());
    for stat in Stat::ALL {
        let key = (stat as u32).to_ne_bytes();
        let total: u64 = match map.lookup_percpu(&key, MapFlags::ANY) {
            Ok(Some(per_cpu)) => per_cpu
                .iter()
                .map(|raw| {
                    let mut buf = [0u8; 8];
                    let n = raw.len().min(8);
                    buf[..n].copy_from_slice(&raw[..n]);
                    u64::from_ne_bytes(buf)
                })
                .sum(),
            Ok(None) => 0,
            Err(err) => {
                return Err(err).with_context(|| format!("read stats slot {}", stat.name()))
            }
        };
        out.push((stat.name(), total));
    }
    Ok(DataplaneStats { values: out })
}

/// Render a Prometheus exposition body. Dependency-free on purpose: the
/// exporter is a tiny read-only process and should not pull a web framework.
pub fn prometheus_body(
    stats: &DataplaneStats,
    apply_fail_total: u64,
    last_apply_unix: Option<i64>,
    extra: &[(&str, &str, f64)],
) -> String {
    let mut out = String::with_capacity(4096);
    for stat in Stat::ALL {
        let name = format!("waf_sklookup_{}_total", stat.name());
        let _ = writeln!(out, "# HELP {name} {}", stat.help());
        let _ = writeln!(out, "# TYPE {name} counter");
        let _ = writeln!(out, "{name} {}", stats.get(stat.name()));
    }

    let _ = writeln!(
        out,
        "# HELP waf_sklookup_apply_fail_total Desired-state applies rejected by the control plane"
    );
    let _ = writeln!(out, "# TYPE waf_sklookup_apply_fail_total counter");
    let _ = writeln!(out, "waf_sklookup_apply_fail_total {apply_fail_total}");

    let _ = writeln!(
        out,
        "# HELP waf_sklookup_last_apply_central_seconds Unix time of the last accepted central apply"
    );
    let _ = writeln!(out, "# TYPE waf_sklookup_last_apply_central_seconds gauge");
    let _ = writeln!(
        out,
        "waf_sklookup_last_apply_central_seconds {}",
        last_apply_unix.unwrap_or(0)
    );

    for (name, help, value) in extra {
        let full = format!("waf_sklookup_{name}");
        let _ = writeln!(out, "# HELP {full} {help}");
        let _ = writeln!(out, "# TYPE {full} gauge");
        let _ = writeln!(out, "{full} {value}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tmp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("waf-metrics-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn apply_fail_counter_increments_and_persists() {
        let dir = tmp("fail");
        let path = dir.join("apply_fail_total");
        assert_eq!(read(&path), 0);
        increment(&path);
        increment(&path);
        assert_eq!(read(&path), 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_stamp_roundtrips() {
        let dir = tmp("stamp");
        let path = dir.join("last-apply-central");
        write_apply_stamp(&path).unwrap();
        let stamp = read_apply_stamp(&path).unwrap();
        assert!(apply_stamp_unix(&stamp).is_some(), "{stamp}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn stamp_epoch_conversion_is_correct() {
        assert_eq!(apply_stamp_unix("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(apply_stamp_unix("2000-03-01T00:00:00Z"), Some(951868800));
        // Cross-checked with `date -u -d 2026-08-16T07:30:00Z +%s`.
        assert_eq!(apply_stamp_unix("2026-08-16T07:30:00Z"), Some(1786865400));
        assert_eq!(apply_stamp_unix("garbage"), None);
        assert!(apply_stamp_unix(&rfc3339_now()).is_some());
    }

    #[test]
    fn stat_names_are_unique_and_slots_stable() {
        let mut names: Vec<_> = Stat::ALL.iter().map(|s| s.name()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before, "duplicate stat names");
        assert_eq!(Stat::AssignOk as u32, 0);
        assert_eq!(Stat::ShardFallback as u32, 11);
    }

    #[test]
    fn stat_slots_match_bpf_source() {
        let src = include_str!("../../../dispatch.bpf.c");
        for slot in [
            "STAT_ASSIGN_OK = 0",
            "STAT_PORT_MISS = 1",
            "STAT_NO_SLOT = 2",
            "STAT_INVALID_GROUP = 3",
            "STAT_ERR_EEXIST = 4",
            "STAT_ERR_EAFNOSUPPORT = 5",
            "STAT_ERR_ESOCKTNOSUPPORT = 6",
            "STAT_ERR_EPROTOTYPE = 7",
            "STAT_ERR_OTHER = 8",
            "STAT_PASS_NON_TCP = 9",
            "STAT_PASS_BAD_FAMILY = 10",
            "STAT_SHARD_FALLBACK = 11",
        ] {
            assert!(src.contains(slot), "dispatch.bpf.c must define {slot}");
        }
    }

    #[test]
    fn fault_ratio_only_counts_faults() {
        let stats = DataplaneStats {
            values: vec![
                ("assign_ok", 90),
                ("no_slot", 10),
                ("port_miss", 1000),
                ("pass_non_tcp", 500),
            ],
        };
        assert_eq!(stats.total_faults(), 10);
        // port_miss / pass_non_tcp are normal fall-through, not faults.
        assert_eq!(stats.fault_ratio(), Some(0.1));
        assert_eq!(DataplaneStats::default().fault_ratio(), None);
    }

    // SDD-001 / T-005: map pressure is an operational contract, not an
    // ad-hoc division in the HTTP exporter. The snapshot must preserve the
    // same entries/capacity pair for every derived value.
    #[test]
    fn capacity_snapshot_reports_consistent_pressure_and_headroom() {
        let c = CapacitySnapshot::new(60_000, 131_072).unwrap();
        assert_eq!(c.entries, 60_000);
        assert_eq!(c.capacity, 131_072);
        assert_eq!(c.headroom, 71_072);
        assert!((c.pressure_ratio - 0.457763671875).abs() < 1e-12);
        assert!(CapacitySnapshot::new(131_073, 131_072).is_none());
        assert!(CapacitySnapshot::new(1, 0).is_none());
    }

    #[test]
    fn rejection_reason_is_bounded_and_persisted() {
        assert_eq!(
            classify_rejection("binding 127.0.0.1:9101 conflicts with reserved endpoint"),
            "reservation"
        );
        assert_eq!(classify_rejection("tenant port quota exceeded"), "capacity");
        assert_eq!(
            classify_rejection("untrusted free-form 10.0.0.1 tenant=acme"),
            "other"
        );
        let dir = std::env::temp_dir().join(format!("waf-metrics-{}", std::process::id()));
        let metrics = dir.join("apply_fail_total");
        record_rejection(&metrics, "port 9101 is reserved by policy");
        assert_eq!(read(&metrics), 1);
        assert_eq!(
            read_last_rejection(&metrics).as_deref(),
            Some("reservation")
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn prometheus_body_is_well_formed() {
        let stats = DataplaneStats {
            values: vec![("assign_ok", 5), ("no_slot", 1)],
        };
        let body = prometheus_body(
            &stats,
            3,
            Some(1786944600),
            &[("listen_shards", "live shards", 4.0)],
        );
        assert!(body.contains("# TYPE waf_sklookup_assign_ok_total counter"));
        assert!(body.contains("waf_sklookup_assign_ok_total 5"));
        assert!(body.contains("waf_sklookup_no_slot_total 1"));
        assert!(body.contains("waf_sklookup_apply_fail_total 3"));
        assert!(body.contains("waf_sklookup_last_apply_central_seconds 1786944600"));
        assert!(body.contains("waf_sklookup_listen_shards 4"));
        for stat in Stat::ALL {
            assert!(
                body.contains(&format!("waf_sklookup_{}_total ", stat.name())),
                "missing {}",
                stat.name()
            );
        }
    }
}
