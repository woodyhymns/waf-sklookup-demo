//! Discover OpenResty LISTEN inode via `/proc/net/tcp` + `pidfd_getfd` (IPv4 only).

use std::fs::{self, File};
use std::net::Ipv4Addr;
use std::os::fd::{FromRawFd, OwnedFd, RawFd}; // OwnedFd held for SOCKMAP lifetime
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};

pub fn find_listen_socket_file(host: &str, port: u16) -> Result<OwnedFd> {
    let ip: Ipv4Addr = host
        .parse()
        .with_context(|| format!("invalid host {host:?}"))?;
    let data = fs::read_to_string("/proc/net/tcp").context("read /proc/net/tcp")?;
    let inode = match parse_listen_inode(&data, ip, port) {
        Ok(ino) => ino,
        Err(_) => parse_listen_inode(&data, Ipv4Addr::UNSPECIFIED, port)
            .with_context(|| format!("no LISTEN socket for {ip}:{port}"))?,
    };
    let f = open_socket_by_inode(inode)?;
    crate::log_msg(format_args!(
        "discovered listen socket inode={inode} for {ip}:{port}"
    ));
    Ok(f)
}

pub fn parse_listen_inode(table: &str, ip: Ipv4Addr, port: u16) -> Result<u64> {
    let want_port = format!("{port:04X}");
    let want_addr = format!("{:08X}", ip_to_proc_hex(ip));
    let mut lines = table.lines();
    if lines.next().is_none() {
        bail!("empty /proc/net/tcp");
    }
    for line in lines {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        let local = fields[1];
        let state = fields[3];
        if state != "0A" {
            continue;
        }
        let Some((addr, port_hex)) = local.split_once(':') else {
            continue;
        };
        if !port_hex.eq_ignore_ascii_case(&want_port) || !addr.eq_ignore_ascii_case(&want_addr) {
            continue;
        }
        if let Ok(inode) = fields[9].parse::<u64>() {
            return Ok(inode);
        }
    }
    bail!("no LISTEN socket for {ip}:{port}")
}

pub fn ip_to_proc_hex(ip: Ipv4Addr) -> u32 {
    let o = ip.octets();
    u32::from(o[0]) | u32::from(o[1]) << 8 | u32::from(o[2]) << 16 | u32::from(o[3]) << 24
}

fn open_socket_by_inode(inode: u64) -> Result<OwnedFd> {
    let want = format!("socket:[{inode}]");
    let mut last_err: Option<anyhow::Error> = None;
    let proc_entries = fs::read_dir("/proc").context("read /proc")?;
    for ent in proc_entries.flatten() {
        let name = ent.file_name();
        let name = name.to_string_lossy();
        if !is_pid_name(&name) {
            continue;
        }
        let pid: i32 = match name.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let fd_dir = PathBuf::from("/proc").join(name.as_ref()).join("fd");
        let fds = match fs::read_dir(&fd_dir) {
            Ok(d) => d,
            Err(_) => continue,
        };
        for fdent in fds.flatten() {
            let path = fd_dir.join(fdent.file_name());
            let target = match fs::read_link(&path) {
                Ok(t) => t,
                Err(_) => continue,
            };
            if target.to_string_lossy() != want {
                continue;
            }
            let fd_num: i32 = match fdent.file_name().to_string_lossy().parse() {
                Ok(n) => n,
                Err(_) => continue,
            };
            match dup_foreign_socket(pid, fd_num) {
                Ok(f) => return Ok(f),
                Err(err) => last_err = Some(err),
            }
        }
    }
    if let Some(err) = last_err {
        return Err(err).context(format!("socket inode {inode} found but dup failed"));
    }
    bail!("socket inode {inode} not found under /proc/*/fd")
}

/// `open(/proc/pid/fd/N)` returns ENXIO for sockets on some kernels; pidfd_getfd works (Linux ≥ 5.6).
fn dup_foreign_socket(pid: i32, fd: i32) -> Result<OwnedFd> {
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) };
    if pidfd < 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("pidfd_open({pid})"));
    }
    let pidfd = pidfd as RawFd;
    let sockfd = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd, fd, 0u32) };
    unsafe {
        libc::close(pidfd);
    }
    if sockfd < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("pidfd_getfd(pid={pid} fd={fd})"));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(sockfd as RawFd) })
}

pub fn is_pid_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|c| c.is_ascii_digit())
}

/// Keep a dup of `fd` so the SOCKMAP entry stays valid for the loader lifetime.
pub fn dup_fd(fd: &impl AsRawFd) -> Result<OwnedFd> {
    let n = unsafe { libc::dup(fd.as_raw_fd()) };
    if n < 0 {
        return Err(std::io::Error::last_os_error()).context("dup");
    }
    Ok(unsafe { OwnedFd::from_raw_fd(n) })
}

#[allow(dead_code)]
pub fn owned_from_file(f: File) -> OwnedFd {
    OwnedFd::from(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_listen_inode_ok() {
        let table = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
             0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4242 1 0000000000000000 100 0 0 10 0\n";
        let inode = parse_listen_inode(table, Ipv4Addr::new(127, 0, 0, 1), 8080).unwrap();
        assert_eq!(inode, 4242);
        assert!(parse_listen_inode(table, Ipv4Addr::new(127, 0, 0, 1), 18081).is_err());
    }

    #[test]
    fn ip_to_proc_hex_loopback() {
        assert_eq!(ip_to_proc_hex(Ipv4Addr::new(127, 0, 0, 1)), 0x0100_007F);
    }
}
