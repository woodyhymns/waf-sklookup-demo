//! `-mode toy`: TCP listen + sockmap slot 0 + tiny HTTP.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

use anyhow::{Context, Result};

use crate::dispatch::DispatchSkel;
use crate::listen_fd;
use crate::load::{open_steered_ports, register_listen_fd};
use crate::pin::REDIR_PRIMARY;

pub fn run_toy_mode(
    skel: &DispatchSkel<'_>,
    listen_addr: &str,
    steered_ports: &[u16],
    shutdown: &Arc<AtomicBool>,
) -> Result<std::os::fd::OwnedFd> {
    let listener =
        TcpListener::bind(listen_addr).with_context(|| format!("listen {listen_addr}"))?;
    let held = listen_fd::dup_fd(&listener)?;
    register_listen_fd(&skel.maps.redir_socket, held.as_raw_fd(), REDIR_PRIMARY)?;
    open_steered_ports(&skel.maps.open_ports, steered_ports, REDIR_PRIMARY as u8)?;

    let listen_owned = listen_addr.to_string();
    let stop = Arc::clone(shutdown);
    listener.set_nonblocking(true).context("set nonblocking")?;
    thread::spawn(move || {
        crate::log_msg(format_args!(
            "HTTP server serving on {listen_owned} (and steered ports)"
        ));
        while !stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let addr = listen_owned.clone();
                    thread::spawn(move || {
                        if let Err(err) = handle_http(stream, &addr) {
                            crate::log_msg(format_args!("toy http: {err:#}"));
                        }
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    crate::log_msg(format_args!("accept: {e}"));
                    thread::sleep(std::time::Duration::from_millis(50));
                }
            }
        }
    });

    print_toy_instructions(listen_addr, steered_ports);
    Ok(held)
}

fn handle_http(mut stream: TcpStream, listen_addr: &str) -> Result<()> {
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf)?;
    let req = String::from_utf8_lossy(&buf[..n]);
    let mut path = "/";
    let mut host = "";
    if let Some(first) = req.lines().next() {
        let parts: Vec<&str> = first.split_whitespace().collect();
        if parts.len() >= 2 {
            path = parts[1];
        }
    }
    for line in req.lines() {
        if let Some(rest) = line.strip_prefix("Host:") {
            host = rest.trim();
            break;
        }
        if let Some(rest) = line.strip_prefix("host:") {
            host = rest.trim();
            break;
        }
    }
    let local = stream
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "?".into());
    let remote = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "?".into());
    let body = format!(
        "sk_lookup demo OK\nserver_listen={listen_addr}\nhttp_local_addr={local}\nremote={remote}\nhost={host}\npath={path}\n"
    );
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(resp.as_bytes())?;
    Ok(())
}

fn print_toy_instructions(listen_addr: &str, steered_ports: &[u16]) {
    let (mut host, real_port) = split_host_port(listen_addr);
    if host.is_empty() || host == "0.0.0.0" {
        host = "127.0.0.1".into();
    }
    println!("======== TOY DEMO READY ========");
    println!("Real bind:   curl -sS http://{host}:{real_port}/");
    for port in steered_ports {
        println!("Steered:     curl -sS http://{host}:{port}/");
    }
    println!("Without BPF those steered ports would fail to connect.");
    println!("Ctrl+C to stop.");
    println!("================================");
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
