//! Batched map update/delete + per-key fallback (parity with `ports_bulk.go`).

use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use libbpf_rs::{ErrorKind, MapCore, MapFlags, MapHandle};

use crate::key::{PortKey, PortVal, PORT_KEY_SIZE, PORT_VAL_SIZE};
use crate::pin::{open_ports_path, DEFAULT_BULK_BATCH, REDIR_TLS};

#[derive(Debug, Clone, Default)]
pub struct BulkResult {
    pub n: usize,
    pub elapsed: Duration,
    pub used_batch: bool,
    pub missing: usize,
}

pub fn load_pinned_open_ports(pin_dir: &Path) -> Result<MapHandle> {
    // This check happens before returning a writable map handle, so every
    // second-process path (ctl, socket control plane, bulk fill/close) refuses
    // to mutate a map owned by a different BPF program. A missing sidecar is
    // tolerated for a one-time upgrade from older deployments.
    let _ = crate::identity::assert_pinned_program_matches(pin_dir)?;
    let path = open_ports_path(pin_dir);
    MapHandle::from_pinned_path(&path).with_context(|| {
        format!(
            "load pinned open_ports: {} (is the loader still running?)",
            path.display()
        )
    })
}

/// Verify the pinned map really uses the layout this binary was built for.
///
/// The previous code silently truncated or zero-padded keys to whatever
/// `key_size()` reported. Against a map from a different build that produces
/// well-formed writes to the *wrong* keys, which is far worse than refusing:
/// ports would appear to open while the dataplane steered nothing.
fn check_layout(map: &impl MapCore) -> Result<()> {
    let (k, v) = (map.key_size() as usize, map.value_size() as usize);
    if k != PORT_KEY_SIZE || v != PORT_VAL_SIZE {
        anyhow::bail!(
            "pinned open_ports layout is key={k} value={v}, expected key={PORT_KEY_SIZE} \
             value={PORT_VAL_SIZE}; the running dataplane was built from different \
             sources (re-pin after restarting the loader)"
        );
    }
    Ok(())
}

fn pack_keys(keys: &[PortKey]) -> Vec<u8> {
    let mut out = Vec::with_capacity(PORT_KEY_SIZE * keys.len());
    for k in keys {
        out.extend_from_slice(&k.to_bytes());
    }
    out
}

fn pack_values(n: usize, group: u8, shards: u8) -> Vec<u8> {
    let val = PortVal::new(group, shards).to_bytes();
    let mut out = Vec::with_capacity(PORT_VAL_SIZE * n);
    for _ in 0..n {
        out.extend_from_slice(&val);
    }
    out
}

fn is_missing_key(err: &libbpf_rs::Error) -> bool {
    err.kind() == ErrorKind::NotFound
}

/// Batched put. `shards` is the live worker count for `group`; see
/// `openresty::max_shards`.
/// Snapshot exactly the keys a mutation is about to change. `None` means the
/// key did not exist. Callers use this before map-first mutations so a failed
/// desired-state file commit can restore the prior dataplane precisely.
pub fn snapshot_keys(
    map: &MapHandle,
    keys: &[PortKey],
) -> Result<std::collections::BTreeMap<PortKey, Option<PortVal>>> {
    check_layout(map)?;
    let mut snapshot = std::collections::BTreeMap::new();
    for key in keys {
        let value = map.lookup(&key.to_bytes(), MapFlags::ANY)?;
        let parsed = value.as_deref().map(PortVal::from_bytes);
        snapshot.insert(*key, parsed);
    }
    Ok(snapshot)
}

/// Restore a snapshot after a mutation fails after touching the map. This uses
/// individual operations deliberately: recovery correctness matters more than
/// batching and it handles keys that were previously absent.
pub fn restore_snapshot(
    map: &MapHandle,
    snapshot: &std::collections::BTreeMap<PortKey, Option<PortVal>>,
) -> Result<()> {
    check_layout(map)?;
    for (key, value) in snapshot {
        match value {
            Some(value) => map.update(&key.to_bytes(), &value.to_bytes(), MapFlags::ANY)?,
            None => match map.delete(&key.to_bytes()) {
                Ok(()) => {}
                Err(err) if is_missing_key(&err) => {}
                Err(err) => return Err(err.into()),
            },
        }
    }
    Ok(())
}

pub fn bulk_put_keys(
    map: &MapHandle,
    ports: &[PortKey],
    slot: u8,
    shards: u8,
    batch_size: usize,
    mut progress: Option<&mut dyn Write>,
) -> Result<BulkResult> {
    let mut res = BulkResult::default();
    if ports.is_empty() {
        return Ok(res);
    }
    check_layout(map)?;
    let shards = shards.max(1);
    let batch_size = if batch_size == 0 {
        DEFAULT_BULK_BATCH
    } else {
        batch_size
    };
    let start = Instant::now();
    let mut use_batch = true;
    let mut done = 0usize;
    let mut i = 0usize;
    while i < ports.len() {
        let end = (i + batch_size).min(ports.len());
        let chunk = &ports[i..end];
        if use_batch {
            let keys = pack_keys(chunk);
            let vals = pack_values(chunk.len(), slot, shards);
            match map.update_batch(
                &keys,
                &vals,
                chunk.len() as u32,
                MapFlags::ANY,
                MapFlags::ANY,
            ) {
                Ok(()) => {
                    done += chunk.len();
                    res.used_batch = true;
                }
                Err(err) if done == 0 => {
                    eprintln!(
                        "{} BPF batch update unavailable ({err}); falling back to per-key put (still O(n))",
                        crate::log_prefix()
                    );
                    use_batch = false;
                    continue;
                }
                Err(err) => {
                    res.n = done;
                    res.elapsed = start.elapsed();
                    res.used_batch = true;
                    return Err(err).with_context(|| format!("batch update at offset {i}"));
                }
            }
        } else {
            for p in chunk {
                map.update(
                    &p.to_bytes(),
                    &PortVal::new(slot, shards).to_bytes(),
                    MapFlags::ANY,
                )
                .with_context(|| format!("put {p}"))?;
                done += 1;
            }
        }
        i = end;
        if let Some(w) = progress.as_mut() {
            report_bulk_progress(w, "add", done, ports.len(), start)?;
        }
    }
    res.n = done;
    res.elapsed = start.elapsed();
    Ok(res)
}

pub fn bulk_delete_keys(
    map: &MapHandle,
    ports: &[PortKey],
    batch_size: usize,
    mut progress: Option<&mut dyn Write>,
) -> Result<BulkResult> {
    let mut res = BulkResult::default();
    if ports.is_empty() {
        return Ok(res);
    }
    check_layout(map)?;
    let batch_size = if batch_size == 0 {
        DEFAULT_BULK_BATCH
    } else {
        batch_size
    };
    let start = Instant::now();
    let mut done = 0usize;
    let mut i = 0usize;
    while i < ports.len() {
        let end = (i + batch_size).min(ports.len());
        let chunk = &ports[i..end];
        let keys = pack_keys(chunk);
        match map.delete_batch(&keys, chunk.len() as u32, MapFlags::ANY, MapFlags::ANY) {
            Ok(()) => {
                done += chunk.len();
                res.used_batch = true;
            }
            Err(_) => {
                for p in chunk {
                    match map.delete(&p.to_bytes()) {
                        Ok(()) => done += 1,
                        Err(err) if is_missing_key(&err) => {
                            res.missing += 1;
                            done += 1;
                        }
                        Err(err) => {
                            res.n = done;
                            res.elapsed = start.elapsed();
                            return Err(err).with_context(|| format!("delete {p}"));
                        }
                    }
                }
            }
        }
        i = end;
        if let Some(w) = progress.as_mut() {
            report_bulk_progress(w, "remove", done, ports.len(), start)?;
        }
    }
    res.n = done;
    res.elapsed = start.elapsed();
    Ok(res)
}

pub fn report_bulk_progress(
    w: &mut dyn Write,
    op: &str,
    done: usize,
    total: usize,
    start: Instant,
) -> Result<()> {
    if total == 0 {
        return Ok(());
    }
    if total < 256 && done < total {
        return Ok(());
    }
    let elapsed = start.elapsed();
    let pct = (done as f64) * 100.0 / (total as f64);
    let rate = if elapsed.as_secs_f64() > 0.0 {
        format!(" rate={:.0}/s", done as f64 / elapsed.as_secs_f64())
    } else {
        String::new()
    };
    writeln!(
        w,
        "{op} {done}/{total} ({pct:.1}%) elapsed={}{rate}",
        fmt_duration(elapsed)
    )?;
    Ok(())
}

pub fn format_bulk_summary(op: &str, n: usize, slot: u8, res: &BulkResult) -> String {
    let label = if slot == REDIR_TLS as u8 {
        "tls-fallback"
    } else {
        "primary"
    };
    let extra = if res.missing > 0 {
        format!(" missing={}", res.missing)
    } else {
        String::new()
    };
    let batch = if res.used_batch { "batch" } else { "per-key" };
    format!(
        "{op} n={n} slot={slot} ({label}) elapsed={} method={batch}{extra}",
        fmt_duration(res.elapsed)
    )
}

pub fn format_remove_summary(res: &BulkResult) -> String {
    let extra = if res.missing > 0 {
        format!(" missing={}", res.missing)
    } else {
        String::new()
    };
    let batch = if res.used_batch { "batch" } else { "per-key" };
    format!(
        "removed n={} elapsed={} method={batch}{extra}",
        res.n,
        fmt_duration(res.elapsed)
    )
}

pub fn fmt_duration(d: Duration) -> String {
    let ns = d.as_nanos();
    if ns == 0 {
        return "0s".into();
    }
    if ns < 1_000_000_000 {
        let ms = d.as_millis();
        if ns < 1_000_000 {
            let us = d.as_micros();
            if ns < 1_000 {
                return format!("{ns}ns");
            }
            return format!("{us}µs");
        }
        return format!("{ms}ms");
    }
    let secs = d.as_secs_f64();
    if (secs - secs.round()).abs() < 1e-9 {
        format!("{}s", secs.round() as u64)
    } else {
        let trimmed = format!("{secs:.3}");
        let trimmed = trimmed.trim_end_matches('0').trim_end_matches('.');
        format!("{trimmed}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packed_keys_are_exact_stride_not_truncated() {
        // The old helper padded/truncated to key_size(); a stride mismatch here
        // writes valid entries under the wrong keys.
        let keys = [PortKey::wildcard_v4(18081), PortKey::wildcard_v4(18082)];
        let packed = pack_keys(&keys);
        assert_eq!(packed.len(), PORT_KEY_SIZE * 2);
        assert_eq!(
            PortKey::from_bytes(&packed[PORT_KEY_SIZE..]).unwrap(),
            keys[1]
        );
    }

    #[test]
    fn packed_values_carry_group_and_shards() {
        let packed = pack_values(3, 1, 4);
        assert_eq!(packed.len(), PORT_VAL_SIZE * 3);
        for i in 0..3 {
            let v = PortVal::from_bytes(&packed[i * PORT_VAL_SIZE..]);
            assert_eq!((v.group, v.shards), (1, 4));
        }
    }

    #[test]
    fn format_bulk_summary_ok() {
        let s = format_bulk_summary("added", 30000, 0, &BulkResult::default());
        assert!(s.contains("added n=30000"), "{s}");
        assert!(s.contains("primary"), "{s}");
    }

    #[test]
    fn report_progress_large_total() {
        let mut buf = Vec::new();
        report_bulk_progress(&mut buf, "add", 4096, 30000, Instant::now()).unwrap();
        assert!(!buf.is_empty());
    }
}
