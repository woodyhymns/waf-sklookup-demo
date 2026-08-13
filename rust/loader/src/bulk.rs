//! Batched map update/delete + per-key fallback (parity with `ports_bulk.go`).

use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use libbpf_rs::{ErrorKind, MapCore, MapFlags, MapHandle};

use crate::pin::{open_ports_path, DEFAULT_BULK_BATCH, REDIR_TLS};

#[derive(Debug, Clone, Default)]
pub struct BulkResult {
    pub n: usize,
    pub elapsed: Duration,
    pub used_batch: bool,
    pub missing: usize,
}

pub fn load_pinned_open_ports(pin_dir: &Path) -> Result<MapHandle> {
    let path = open_ports_path(pin_dir);
    MapHandle::from_pinned_path(&path).with_context(|| {
        format!(
            "load pinned open_ports: {} (is the loader still running?)",
            path.display()
        )
    })
}

fn port_key_bytes(map: &impl MapCore, port: u16) -> Vec<u8> {
    let mut key = vec![0u8; map.key_size() as usize];
    let b = port.to_ne_bytes();
    let n = key.len().min(b.len());
    key[..n].copy_from_slice(&b[..n]);
    key
}

fn slot_value_bytes(map: &impl MapCore, slot: u8) -> Vec<u8> {
    let mut val = vec![0u8; map.value_size() as usize];
    if !val.is_empty() {
        val[0] = slot;
    }
    val
}

fn pack_keys(map: &impl MapCore, ports: &[u16]) -> Vec<u8> {
    let sz = map.key_size() as usize;
    let mut out = vec![0u8; sz * ports.len()];
    for (i, p) in ports.iter().enumerate() {
        let b = p.to_ne_bytes();
        let n = sz.min(b.len());
        out[i * sz..i * sz + n].copy_from_slice(&b[..n]);
    }
    out
}

fn pack_slot_values(map: &impl MapCore, n: usize, slot: u8) -> Vec<u8> {
    let sz = map.value_size() as usize;
    let mut out = vec![0u8; sz * n];
    if sz == 0 {
        return out;
    }
    for i in 0..n {
        out[i * sz] = slot;
    }
    out
}

fn is_missing_key(err: &libbpf_rs::Error) -> bool {
    err.kind() == ErrorKind::NotFound
}

pub fn bulk_put_ports(
    map: &MapHandle,
    ports: &[u16],
    slot: u8,
    batch_size: usize,
    mut progress: Option<&mut dyn Write>,
) -> Result<BulkResult> {
    let mut res = BulkResult::default();
    if ports.is_empty() {
        return Ok(res);
    }
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
            let keys = pack_keys(map, chunk);
            let vals = pack_slot_values(map, chunk.len(), slot);
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
                let key = port_key_bytes(map, *p);
                let val = slot_value_bytes(map, slot);
                map.update(&key, &val, MapFlags::ANY)
                    .with_context(|| format!("put port {p}"))?;
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

pub fn bulk_delete_ports(
    map: &MapHandle,
    ports: &[u16],
    batch_size: usize,
    mut progress: Option<&mut dyn Write>,
) -> Result<BulkResult> {
    let mut res = BulkResult::default();
    if ports.is_empty() {
        return Ok(res);
    }
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
        let keys = pack_keys(map, chunk);
        match map.delete_batch(&keys, chunk.len() as u32, MapFlags::ANY, MapFlags::ANY) {
            Ok(()) => {
                done += chunk.len();
                res.used_batch = true;
            }
            Err(_) => {
                for p in chunk {
                    let key = port_key_bytes(map, *p);
                    match map.delete(&key) {
                        Ok(()) => done += 1,
                        Err(err) if is_missing_key(&err) => {
                            res.missing += 1;
                            done += 1;
                        }
                        Err(err) => {
                            res.n = done;
                            res.elapsed = start.elapsed();
                            return Err(err).with_context(|| format!("delete port {p}"));
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
