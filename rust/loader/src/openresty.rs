//! `-mode openresty`: capture every worker listen FD and shard them across
//! `redir_socket`.
//!
//! What changed and why:
//!
//! * The old code captured **one** listen socket per protocol group. With
//!   `SO_REUSEPORT` (which production nginx uses) every worker owns its own
//!   listen socket, so the entire steered-port dataplane hung off a single
//!   worker. When that worker exited, `bpf_sk_assign` returned
//!   -ESOCKTNOSUPPORT and the program dropped the SYN — every steered port went
//!   dark while natively-bound ports kept serving. Now all worker sockets are
//!   captured and registered as shards, so one dead worker costs 1/N.
//!
//! * `rescan_slot` compared the inode of the FD it held against a *freshly
//!   captured* FD. That can only detect "a different socket now exists at this
//!   address"; it cannot detect "the socket I am holding stopped listening".
//!   Rescan now validates liveness (`SO_ACCEPTCONN` plus presence in
//!   `/proc/net/tcp` LISTEN state) before deciding nothing changed.

use std::net::SocketAddr;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use libbpf_rs::MapCore;

use crate::listen_fd::{self, CapturedListen};
use crate::load::{open_steered_ports, register_listen_fd_shard, unregister_listen_shard};
use crate::pin::{REDIR_PRIMARY, REDIR_TLS, SHARD_STRIDE};

/// Listen sockets registered for one protocol group.
pub struct ShardSet {
    pub group: u32,
    pub target: String,
    /// Held FDs, index = shard. The dup keeps the sockmap entry valid.
    pub shards: Vec<CapturedListen>,
}

impl ShardSet {
    pub fn len(&self) -> u8 {
        self.shards.len().min(SHARD_STRIDE as usize) as u8
    }

    pub fn is_empty(&self) -> bool {
        self.shards.is_empty()
    }

    pub fn inodes(&self) -> Vec<u64> {
        self.shards.iter().map(|c| c.inode).collect()
    }
}

fn split_target(target: &str) -> Result<(String, u16)> {
    let (mut host, port_raw) = split_host_port(target);
    if host.is_empty() {
        host = "0.0.0.0".into();
    }
    let port: u16 = port_raw
        .parse()
        .with_context(|| format!("bad listen port {port_raw:?}"))?;
    Ok((host, port))
}

/// Capture all worker listen sockets for `target` and register them as shards
/// of `group`. Returns the registered set.
pub fn register_shards(redir: &dyn MapCore, target: &str, group: u32) -> Result<ShardSet> {
    let (host, port) = split_target(target)?;
    let mut captured = listen_fd::capture_all_listen_sockets(&host, port)?;

    if captured.len() > SHARD_STRIDE as usize {
        crate::log_msg(format_args!(
            "warning: {} listen sockets for {target} exceeds SHARD_STRIDE {}; using the first {}",
            captured.len(),
            SHARD_STRIDE,
            SHARD_STRIDE
        ));
        captured.truncate(SHARD_STRIDE as usize);
    }

    for (shard, entry) in captured.iter().enumerate() {
        register_listen_fd_shard(redir, entry.fd.as_raw_fd(), group, shard as u32)?;
    }
    crate::log_msg(format_args!(
        "registered {} listen shard(s) for {target} in group {group} (inodes {:?})",
        captured.len(),
        captured.iter().map(|c| c.inode).collect::<Vec<_>>()
    ));
    Ok(ShardSet {
        group,
        target: target.to_string(),
        shards: captured,
    })
}

/// Re-capture the worker set and update the sockmap if it changed.
///
/// Returns the number of shard slots that were rewritten. Zero means the live
/// worker set is byte-for-byte what we already registered *and* every held FD
/// is still listening.
pub fn rescan_shards(redir: &dyn MapCore, set: &mut ShardSet) -> Result<usize> {
    let (host, port) = split_target(&set.target)?;

    // A held FD that left LISTEN state is the failure the old inode comparison
    // could not see, so check liveness first and force a refresh if any shard
    // is stale.
    let mut stale = false;
    for entry in &set.shards {
        if !entry.owner_still_owns_listener() {
            // A loader-held duplicate keeps SO_ACCEPTCONN and /proc/net/tcp
            // looking healthy after the original nginx worker dies. The pidfd
            // identifies the *original* process and is immune to PID reuse.
            crate::log_msg(format_args!(
                "shard inode={} owner_pid={} for {} exited or released its listener",
                entry.inode, entry.owner_pid, set.target
            ));
            stale = true;
            break;
        }
        if !listen_fd::fd_is_listening(&entry.fd) {
            crate::log_msg(format_args!(
                "shard inode={} for {} is no longer listening",
                entry.inode, set.target
            ));
            stale = true;
            break;
        }
        if !listen_fd::inode_still_listening(&host, port, entry.inode)? {
            crate::log_msg(format_args!(
                "shard inode={} for {} vanished from /proc/net/tcp LISTEN",
                entry.inode, set.target
            ));
            stale = true;
            break;
        }
    }

    let live_inodes = {
        let mut v = listen_fd::capture_all_listen_sockets(&host, port)
            .map(|c| c.iter().map(|e| e.inode).collect::<Vec<_>>())
            .unwrap_or_default();
        v.sort_unstable();
        v
    };
    let mut held_inodes = set.inodes();
    held_inodes.sort_unstable();

    if !stale && live_inodes == held_inodes {
        return Ok(0);
    }

    let previous = set.shards.len();
    let fresh = register_shards(redir, &set.target, set.group)?;
    let new_len = fresh.shards.len();

    // Drop sockmap entries above the new shard count so the BPF program can
    // never select a slot that points at a dead worker.
    for shard in new_len..previous {
        unregister_listen_shard(redir, set.group, shard as u32)?;
    }

    *set = fresh;
    crate::log_msg(format_args!(
        "rescan-listen refreshed group {} for {}: {previous} -> {new_len} shard(s)",
        set.group, set.target
    ));
    Ok(new_len.max(previous))
}

/// Rescan every registered group. Returns total slots rewritten.
pub fn rescan_held(redir: &dyn MapCore, sets: &mut [ShardSet]) -> Result<usize> {
    let mut changed = 0;
    for set in sets.iter_mut() {
        changed += rescan_shards(redir, set)?;
    }
    Ok(changed)
}

/// Largest shard count across groups; written into `open_ports` values so the
/// BPF program knows the valid shard range.
pub fn max_shards(sets: &[ShardSet]) -> u8 {
    sets.iter().map(|s| s.len()).max().unwrap_or(1).max(1)
}

pub fn run_openresty_mode(
    open_ports: &dyn MapCore,
    redir_socket: &dyn MapCore,
    target_addr: &str,
    steered_ports: &[u16],
    tls_target_addr: &str,
    tls_ports: &[u16],
    wait: Duration,
    shutdown: &Arc<AtomicBool>,
) -> Result<Vec<ShardSet>> {
    crate::log_msg(format_args!(
        "openresty mode: product path is one internal listen ({target_addr}); sk_lookup does not classify HTTP vs TLS"
    ));
    if !tls_ports.is_empty() {
        crate::log_msg(format_args!(
            "STOCK FALLBACK: also registering TLS listen {tls_target_addr} for -tls-ports (stock OpenResty 1.19.3.2 has no https_allow_http)"
        ));
    }

    let mut sets = Vec::new();

    wait_for_listen_socket(target_addr, wait, shutdown)?;
    let primary = register_shards(redir_socket, target_addr, REDIR_PRIMARY)?;
    let primary_shards = primary.len();
    sets.push(primary);
    open_steered_ports(
        open_ports,
        steered_ports,
        REDIR_PRIMARY as u8,
        primary_shards,
    )?;

    if !tls_ports.is_empty() {
        wait_for_listen_socket(tls_target_addr, wait, shutdown)
            .context("stock TLS fallback listen")?;
        let tls = register_shards(redir_socket, tls_target_addr, REDIR_TLS)?;
        let tls_shards = tls.len();
        sets.push(tls);
        open_steered_ports(open_ports, tls_ports, REDIR_TLS as u8, tls_shards)?;
    }

    print_openresty_instructions(target_addr, steered_ports, tls_target_addr, tls_ports);
    Ok(sets)
}

fn wait_for_listen_socket(
    target_addr: &str,
    wait: Duration,
    shutdown: &Arc<AtomicBool>,
) -> Result<()> {
    let (host, port) = split_target(target_addr)?;
    crate::log_msg(format_args!(
        "waiting for listen socket on {target_addr} (timeout {})",
        crate::bulk::fmt_duration(wait)
    ));
    let deadline = Instant::now() + wait;
    let mut next_log = Instant::now();
    loop {
        if shutdown.load(Ordering::SeqCst) {
            bail!("cancelled while waiting for {target_addr}");
        }
        let err = match listen_fd::find_listen_socket_file(&host, port) {
            Ok(_) => return Ok(()),
            Err(err) => err,
        };
        if Instant::now() > deadline {
            bail!("target listen {target_addr} not found: {err:#}");
        }
        if Instant::now() >= next_log {
            crate::log_msg(format_args!("waiting for {target_addr}: {err:#}"));
            next_log = Instant::now() + Duration::from_secs(2);
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

pub fn print_openresty_instructions(
    target_addr: &str,
    steered_ports: &[u16],
    tls_target_addr: &str,
    tls_ports: &[u16],
) {
    let (mut host, _) = split_host_port(target_addr);
    if host.is_empty() || host == "0.0.0.0" {
        host = "127.0.0.1".into();
    }
    println!("======== OPENRESTY P1 READY ========");
    println!("Product: sk_lookup steers external ports to a fixed internal listen.");
    println!("Tengine https_allow_http: that one listen accepts HTTP and TLS.");
    println!("Stock 1.19.3.2: no https_allow_http; -tls-ports is a labeled fallback.");
    println!("Internal HTTP: curl -sS http://{target_addr}/");
    for port in steered_ports {
        println!("Steered HTTP:  curl -sS http://{host}:{port}/");
    }
    if !tls_ports.is_empty() {
        println!("Internal TLS (stock fallback): curl -sk https://{tls_target_addr}/");
        for port in tls_ports {
            println!("Steered TLS (stock fallback):  curl -sk https://{host}:{port}/");
        }
    }
    println!(
        "Default responses omit X-Waf-External-Port; access_log still has $waf_external_port."
    );
    println!("Expose header: WAF_EXPOSE_EXTERNAL_PORT=1 (restart OpenResty).");
    println!("M2 ctl: sudo $LOADER_BIN add|remove|list|bulk  (no OpenResty reload)");
    println!("Close:  sudo $LOADER_BIN remove 18081");
    println!("Reopen: sudo $LOADER_BIN add 18081");
    println!("Legacy: sudo $LOADER_BIN -mode close-port -ports 18081");
    println!("Ctrl+C to stop the loader (OpenResty keeps running).");
    println!("====================================");
}

fn split_host_port(addr: &str) -> (String, String) {
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        return (sa.ip().to_string(), sa.port().to_string());
    }
    match addr.rsplit_once(':') {
        Some((h, p)) => (
            h.trim_start_matches('[').trim_end_matches(']').to_string(),
            p.to_string(),
        ),
        None => (addr.to_string(), String::new()),
    }
}

#[allow(dead_code)]
pub fn pin_dir_display(p: &Path) -> String {
    p.display().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_target_defaults_to_wildcard_host() {
        assert_eq!(
            split_target(":8080").unwrap(),
            ("0.0.0.0".to_string(), 8080)
        );
        assert_eq!(
            split_target("127.0.0.1:18080").unwrap(),
            ("127.0.0.1".to_string(), 18080)
        );
        assert!(split_target("127.0.0.1:notaport").is_err());
    }

    #[test]
    fn max_shards_never_returns_zero() {
        // open_ports values with shards == 0 are rejected by the BPF program,
        // so an empty set must still report at least one shard.
        assert_eq!(max_shards(&[]), 1);
        let empty = ShardSet {
            group: 0,
            target: "127.0.0.1:1".into(),
            shards: Vec::new(),
        };
        assert_eq!(max_shards(&[empty]), 1);
    }

    #[test]
    fn shard_set_len_is_capped_by_stride() {
        let set = ShardSet {
            group: 0,
            target: "127.0.0.1:1".into(),
            shards: Vec::new(),
        };
        assert_eq!(set.len(), 0);
        assert!(set.is_empty());
    }
}
