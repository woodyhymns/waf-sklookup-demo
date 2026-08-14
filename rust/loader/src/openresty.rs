//! `-mode openresty`: wait for listen FD, register sockmap slot 0/1.

use std::net::SocketAddr;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use libbpf_rs::MapCore;

use crate::listen_fd;
use crate::load::{open_steered_ports, register_listen_fd};
use crate::pin::{REDIR_PRIMARY, REDIR_TLS};

fn socket_inode(fd: &OwnedFd) -> Result<u64> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()).context("fstat listen fd");
    }
    Ok(unsafe { stat.assume_init() }.st_ino)
}

pub fn rescan_slot(
    redir: &dyn MapCore,
    target: &str,
    slot: u32,
    held: Option<&OwnedFd>,
) -> Result<Option<OwnedFd>> {
    let (mut host, port_raw) = split_host_port(target);
    if host.is_empty() { host = "0.0.0.0".into(); }
    let port: u16 = port_raw.parse().with_context(|| format!("bad listen port {port_raw:?}"))?;
    let fresh = listen_fd::find_listen_socket_file(&host, port)?;
    if let Some(old) = held {
        if socket_inode(old)? == socket_inode(&fresh)? { return Ok(None); }
    }
    register_listen_fd(redir, fresh.as_raw_fd(), slot)?;
    crate::log_msg(format_args!("rescan-listen swapped redir_socket[{slot}] to live {target}"));
    Ok(Some(fresh))
}

pub fn rescan_held(
    redir: &dyn MapCore,
    target: &str,
    tls_target: Option<&str>,
    held: &mut Vec<OwnedFd>,
) -> Result<usize> {
    let mut changed = 0;
    if let Some(fd) = rescan_slot(redir, target, REDIR_PRIMARY, held.first())? {
        if held.is_empty() { held.push(fd) } else { held[0] = fd };
        changed += 1;
    }
    if let Some(target) = tls_target {
        if let Some(fd) = rescan_slot(redir, target, REDIR_TLS, held.get(1))? {
            if held.len() < 2 { held.push(fd) } else { held[1] = fd };
            changed += 1;
        }
    }
    Ok(changed)
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
) -> Result<Vec<OwnedFd>> {
    crate::log_msg(format_args!(
        "openresty mode: product path is one internal listen ({target_addr}); sk_lookup does not classify HTTP vs TLS"
    ));
    if !tls_ports.is_empty() {
        crate::log_msg(format_args!(
            "STOCK FALLBACK: also registering TLS listen {tls_target_addr} for -tls-ports (stock OpenResty 1.19.3.2 has no https_allow_http)"
        ));
    }

    let mut held = Vec::new();
    let http_file = wait_for_listen_socket(target_addr, wait, shutdown)?;
    register_listen_fd(
        redir_socket,
        http_file.as_raw_fd(),
        REDIR_PRIMARY,
    )?;
    open_steered_ports(open_ports, steered_ports, REDIR_PRIMARY as u8)?;
    held.push(http_file);

    if !tls_ports.is_empty() {
        let tls_file = wait_for_listen_socket(tls_target_addr, wait, shutdown)
            .context("stock TLS fallback listen")?;
        register_listen_fd(redir_socket, tls_file.as_raw_fd(), REDIR_TLS)?;
        open_steered_ports(open_ports, tls_ports, REDIR_TLS as u8)?;
        held.push(tls_file);
    }

    print_openresty_instructions(target_addr, steered_ports, tls_target_addr, tls_ports);
    Ok(held)
}

fn wait_for_listen_socket(
    target_addr: &str,
    wait: Duration,
    shutdown: &Arc<AtomicBool>,
) -> Result<OwnedFd> {
    let (mut host, port_str) = split_host_port(target_addr);
    let port: u16 = port_str
        .parse()
        .with_context(|| format!("bad listen port {port_str:?}"))?;
    if host.is_empty() {
        host = "0.0.0.0".into();
    }
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
            Ok(f) => return Ok(f),
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
