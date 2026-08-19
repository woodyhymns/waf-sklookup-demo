//! Read-only Prometheus exporter over the pinned maps.
//!
//! Deliberately hand-rolled instead of pulling in a web framework: this thread
//! runs inside a process that holds `CAP_BPF` and every dependency added here
//! is new attack surface on a privileged process. The protocol surface we need
//! is "answer GET /metrics with a text body", which is a few dozen lines.
//!
//! It reads the pinned `stats` map rather than a copy held in this process, so
//! `curl localhost:9httpd/metrics` reports what the kernel actually counted
//! even if the loader's own bookkeeping drifted.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use libbpf_rs::{MapCore, MapHandle};

use crate::freeze;
use crate::metrics;
use crate::pin;
use crate::reservation;
use crate::upgrade;

pub struct Handle {
    shutdown: Arc<AtomicBool>,
    addr: String,
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        // Unblock the accept loop so the thread can observe the flag.
        let _ = std::net::TcpStream::connect(&self.addr);
    }
}

pub fn start(addr: String, pin_dir: PathBuf, shutdown: Arc<AtomicBool>) -> Result<Handle> {
    let listener = TcpListener::bind(&addr).with_context(|| format!("bind {addr}"))?;
    listener
        .set_nonblocking(false)
        .context("exporter listener blocking mode")?;
    let stop = Arc::clone(&shutdown);
    let bound = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| addr.clone());

    thread::spawn(move || {
        for stream in listener.incoming() {
            if stop.load(Ordering::SeqCst) {
                break;
            }
            match stream {
                Ok(stream) => {
                    if let Err(err) = serve(stream, &pin_dir) {
                        crate::log_msg(format_args!("metrics request failed: {err:#}"));
                    }
                }
                Err(err) => {
                    crate::log_msg(format_args!("metrics accept failed: {err:#}"));
                    thread::sleep(Duration::from_millis(200));
                }
            }
        }
    });

    Ok(Handle {
        shutdown,
        addr: bound,
    })
}

fn serve(mut stream: TcpStream, pin_dir: &Path) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

    let mut reader = BufReader::new(stream.try_clone().context("clone metrics stream")?);
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .context("read request")?;
    // Drain headers so the client sees a clean response rather than a reset.
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 || line.trim().is_empty() {
            break;
        }
    }

    let path = request_line.split_whitespace().nth(1).unwrap_or("/");
    match path {
        "/metrics" => {
            let body = render(pin_dir).unwrap_or_else(|err| {
                // Still answer with a scrapeable body: a metrics endpoint that
                // 500s during an incident is the worst possible behaviour.
                format!(
                    "# HELP waf_sklookup_exporter_up Exporter could read the pinned maps\n\
                     # TYPE waf_sklookup_exporter_up gauge\n\
                     waf_sklookup_exporter_up 0\n\
                     # error: {}\n",
                    err.to_string().replace('\n', " ")
                )
            });
            write_response(&mut stream, "200 OK", "text/plain; version=0.0.4", &body)
        }
        "/healthz" => {
            let (ready, reason) = healthz(pin_dir);
            let status = if ready {
                "200 OK"
            } else {
                "503 Service Unavailable"
            };
            write_response(&mut stream, status, "text/plain", &format!("{reason}\n"))
        }
        _ => write_response(&mut stream, "404 Not Found", "text/plain", "not found\n"),
    }
}

fn write_response(stream: &mut TcpStream, status: &str, ctype: &str, body: &str) -> Result<()> {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).context("write head")?;
    stream.write_all(body.as_bytes()).context("write body")?;
    stream.flush().context("flush")?;
    Ok(())
}

fn render(pin_dir: &Path) -> Result<String> {
    let stats_map = MapHandle::from_pinned_path(pin::stats_path(pin_dir))
        .with_context(|| format!("open pinned {}", pin::stats_path(pin_dir).display()))?;
    let stats = metrics::read_stats(&stats_map)?;

    let apply_fail = metrics::read(Path::new(metrics::DEFAULT_METRICS_FILE));
    let last_apply = metrics::read_apply_stamp(Path::new(metrics::DEFAULT_APPLY_STAMP))
        .as_deref()
        .and_then(metrics::apply_stamp_unix);

    let mut extra: Vec<(&str, &str, f64)> =
        vec![("exporter_up", "Exporter could read the pinned maps", 1.0)];

    // Live shard occupancy: how many sockmap slots actually hold a socket.
    // This is the metric that makes "one worker died" visible before users
    // notice, and it cannot be derived from the counters alone.
    let occupancy = redir_occupancy(pin_dir).unwrap_or(-1.0);
    extra.push((
        "listen_shards",
        "Populated redir_socket shard slots across all groups",
        occupancy,
    ));

    match open_ports_entries(pin_dir) {
        Ok(entries) => {
            if let Some(capacity) = capacity_extras(entries) {
                extra.extend(capacity);
            } else {
                // A map count above its declared capacity is impossible for a
                // healthy BPF map. Surface an explicit scrape anomaly instead
                // of inventing a negative headroom or plausible ratio.
                extra.push((
                    "open_ports_entries",
                    "Number of steered destinations currently programmed",
                    entries as f64,
                ));
                extra.push((
                    "open_ports_capacity_snapshot_valid",
                    "1 when open_ports capacity metrics came from a valid snapshot",
                    0.0,
                ));
            }
        }
        Err(_) => {
            extra.push((
                "open_ports_entries",
                "Number of steered destinations currently programmed (-1 means unreadable)",
                -1.0,
            ));
            extra.push((
                "open_ports_capacity_snapshot_valid",
                "1 when open_ports capacity metrics came from a valid snapshot",
                0.0,
            ));
        }
    }

    if let Some(ratio) = stats.fault_ratio() {
        extra.push((
            "fault_ratio",
            "Share of steering attempts that failed since boot",
            ratio,
        ));
    }

    let mut body = metrics::prometheus_body(&stats, apply_fail, last_apply, &extra);
    body.push_str(&control_plane_prometheus(pin_dir));
    Ok(body)
}

/// Bounded-control-plane telemetry. These names deliberately carry only a
/// fixed state/reason label set; endpoint addresses, revisions, tenant IDs and
/// journal error text remain in the authenticated status/audit paths.
fn control_plane_prometheus(pin_dir: &Path) -> String {
    let frozen = freeze::is_frozen(Path::new(freeze::DEFAULT_FREEZE_FILE));
    let summary = reservation::summary(pin_dir);
    let rejection = metrics::read_last_rejection(Path::new(metrics::DEFAULT_METRICS_FILE))
        .unwrap_or_else(|| "none".into());
    let phase = match upgrade::read_journal(pin_dir) {
        Ok(Some(journal)) => format!("{:?}", journal.phase).to_ascii_lowercase(),
        Ok(None) => "none".into(),
        Err(_) => "invalid".into(),
    };
    let in_progress = matches!(
        phase.as_str(),
        "prepared" | "activating" | "healthy" | "rollingback" | "rolling_back"
    );
    format!(
        "# HELP waf_sklookup_control_plane_frozen 1 when mutations are stopped by a safety freeze\n\
         # TYPE waf_sklookup_control_plane_frozen gauge\n\
         waf_sklookup_control_plane_frozen {}\n\
         # HELP waf_sklookup_runtime_reservation_state Runtime reservation sidecar state (fixed vocabulary)\n\
         # TYPE waf_sklookup_runtime_reservation_state gauge\n\
         waf_sklookup_runtime_reservation_state{{state=\"{}\"}} 1\n\
         # HELP waf_sklookup_runtime_reservation_endpoints Number of runtime-protected endpoints\n\
         # TYPE waf_sklookup_runtime_reservation_endpoints gauge\n\
         waf_sklookup_runtime_reservation_endpoints {}\n\
         # HELP waf_sklookup_upgrade_phase Current persisted upgrade phase (fixed vocabulary)\n\
         # TYPE waf_sklookup_upgrade_phase gauge\n\
         waf_sklookup_upgrade_phase{{phase=\"{}\"}} 1\n\
         # HELP waf_sklookup_upgrade_in_progress 1 while an upgrade journal is non-terminal\n\
         # TYPE waf_sklookup_upgrade_in_progress gauge\n\
         waf_sklookup_upgrade_in_progress {}\n\
         # HELP waf_sklookup_last_rejection_reason Last bounded control-plane rejection code\n\
         # TYPE waf_sklookup_last_rejection_reason gauge\n\
         waf_sklookup_last_rejection_reason{{reason=\"{}\"}} 1\n",
        if frozen { 1 } else { 0 },
        summary.state,
        summary.endpoint_count,
        phase,
        if in_progress { 1 } else { 0 },
        rejection,
    )
}

fn healthz(pin_dir: &Path) -> (bool, &'static str) {
    if MapHandle::from_pinned_path(pin::stats_path(pin_dir)).is_err() {
        return (false, "dataplane_unreadable");
    }
    if freeze::is_frozen(Path::new(freeze::DEFAULT_FREEZE_FILE)) {
        return (false, "frozen");
    }
    let reservation = reservation::summary(pin_dir);
    if reservation.state != "active" {
        return (false, "reservation_not_active");
    }
    match upgrade::read_journal(pin_dir) {
        Ok(Some(journal)) if !journal.phase.terminal() => (false, "upgrade_in_progress"),
        Ok(_) => (true, "ready"),
        Err(_) => (false, "upgrade_journal_invalid"),
    }
}

fn redir_occupancy(pin_dir: &Path) -> Result<f64> {
    let map = MapHandle::from_pinned_path(pin::redir_socket_path(pin_dir))?;
    let mut populated = 0u32;
    for slot in 0..pin::REDIR_MAX_ENTRIES {
        // SOCKMAP values are not readable as fds, but a populated slot returns
        // a value while an empty one returns None.
        if let Ok(Some(_)) = map.lookup(&slot.to_ne_bytes(), libbpf_rs::MapFlags::ANY) {
            populated += 1;
        }
    }
    Ok(f64::from(populated))
}

/// One capacity snapshot becomes four related gauges. No port, tenant, or
/// address labels are used: map pressure is node-scoped and must stay bounded
/// under a customer port flood.
fn capacity_extras(entries: u64) -> Option<Vec<(&'static str, &'static str, f64)>> {
    let c = metrics::CapacitySnapshot::new(entries, pin::OPEN_PORTS_MAX_ENTRIES as u64)?;
    Some(vec![
        (
            "open_ports_entries",
            "Number of steered destinations currently programmed",
            c.entries as f64,
        ),
        (
            "open_ports_max_entries",
            "Configured maximum number of open_ports BPF map entries",
            c.capacity as f64,
        ),
        (
            "open_ports_pressure_ratio",
            "Share of open_ports map capacity currently programmed",
            c.pressure_ratio,
        ),
        (
            "open_ports_headroom_entries",
            "Remaining open_ports map capacity before hard admission failure",
            c.headroom as f64,
        ),
    ])
}

fn open_ports_entries(pin_dir: &Path) -> Result<u64> {
    let map = MapHandle::from_pinned_path(pin::open_ports_path(pin_dir))?;
    Ok(map.keys().count() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    // SDD-001 / T-005: all capacity values must derive from one entries
    // snapshot and use stable, low-cardinality Prometheus names.
    #[test]
    fn capacity_extras_publish_entries_max_pressure_and_headroom() {
        let extra = capacity_extras(60_000).unwrap();
        assert_eq!(extra.len(), 4);
        assert_eq!(extra[0].0, "open_ports_entries");
        assert_eq!(extra[0].2, 60_000.0);
        assert_eq!(extra[1].0, "open_ports_max_entries");
        assert_eq!(extra[1].2, 131_072.0);
        assert_eq!(extra[2].0, "open_ports_pressure_ratio");
        assert!((extra[2].2 - 0.457763671875).abs() < 1e-12);
        assert_eq!(extra[3].0, "open_ports_headroom_entries");
        assert_eq!(extra[3].2, 71_072.0);
        assert!(capacity_extras(131_073).is_none());
    }

    #[test]
    fn unknown_paths_get_404_and_metrics_gets_a_body() {
        // Exercise the HTTP surface without any BPF maps: the exporter must
        // still answer, because a metrics endpoint that fails closed during an
        // incident hides exactly the signal operators need.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let dir = std::env::temp_dir().join(format!("waf-exporter-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let handle = thread::spawn(move || {
            for _ in 0..2 {
                let (stream, _) = listener.accept().unwrap();
                let _ = serve(stream, &dir);
            }
        });

        let get = |path: &str| -> String {
            use std::io::Read;
            let mut s = TcpStream::connect(addr).unwrap();
            s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
                .unwrap();
            let mut out = String::new();
            s.read_to_string(&mut out).unwrap();
            out
        };

        let metrics_resp = get("/metrics");
        assert!(
            metrics_resp.starts_with("HTTP/1.1 200 OK"),
            "{metrics_resp}"
        );
        assert!(
            metrics_resp.contains("waf_sklookup_exporter_up 0"),
            "missing maps must report exporter_up 0: {metrics_resp}"
        );

        let missing = get("/nope");
        assert!(missing.starts_with("HTTP/1.1 404"), "{missing}");

        handle.join().unwrap();
    }
}
