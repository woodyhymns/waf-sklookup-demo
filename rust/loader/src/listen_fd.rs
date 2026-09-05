//! Discover OpenResty LISTEN inode via `/proc/net/tcp` + `pidfd_getfd` (IPv4 only).
//!
//! A loader-held `dup` of a worker listen keeps `SO_ACCEPTCONN` and the
//! `/proc/net/tcp` LISTEN row alive after that worker exits. Health therefore
//! tracks the *original owner* with a pidfd (immune to PID reuse) and refuses
//! to treat the loader process as an authoritative owner.

use std::fs::{self, File};
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};

/// Listen socket captured from a non-loader process, plus a pidfd for that owner.
#[derive(Debug)]
pub struct CapturedListen {
    pub inode: u64,
    pub fd: OwnedFd,
    pub owner_pid: i32,
    owner_pidfd: OwnedFd,
}

impl CapturedListen {
    /// True only while the original owner is alive and still holds this inode.
    /// The loader duplicate alone is not a liveness signal.
    pub fn owner_still_owns_listener(&self) -> bool {
        !pidfd_exited(&self.owner_pidfd) && process_has_inode(self.owner_pid, self.inode)
    }
}

pub fn find_listen_socket_file(host: &str, port: u16) -> Result<CapturedListen> {
    let ip: Ipv4Addr = host
        .parse()
        .with_context(|| format!("invalid host {host:?}"))?;
    let data = fs::read_to_string("/proc/net/tcp").context("read /proc/net/tcp")?;
    let mut inodes = parse_listen_inodes(&data, ip, port);
    if inodes.is_empty() {
        inodes = parse_listen_inodes(&data, Ipv4Addr::UNSPECIFIED, port);
    }
    let (inode, captured) = first_openable_inode(&inodes, open_socket_by_inode)
        .with_context(|| format!("no live LISTEN socket for {ip}:{port}"))?;
    crate::log_msg(format_args!(
        "discovered listen socket inode={inode} owned by pid={} for {ip}:{port}",
        captured.owner_pid
    ));
    Ok(captured)
}

/// True when `inode` is still a LISTEN socket at `host:port`.
pub fn inode_still_listening(host: &str, port: u16, inode: u64) -> Result<bool> {
    let ip: Ipv4Addr = host
        .parse()
        .with_context(|| format!("invalid host {host:?}"))?;
    let data = fs::read_to_string("/proc/net/tcp").context("read /proc/net/tcp")?;
    let mut inodes = parse_listen_inodes(&data, ip, port);
    if inodes.is_empty() {
        inodes = parse_listen_inodes(&data, Ipv4Addr::UNSPECIFIED, port);
    }
    Ok(inodes.contains(&inode))
}

/// `SO_ACCEPTCONN` on a held FD. Pair with [`CapturedListen::owner_still_owns_listener`].
pub fn fd_is_listening(fd: &OwnedFd) -> bool {
    let mut val: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ACCEPTCONN,
            &mut val as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    rc == 0 && val != 0
}

pub fn parse_listen_inode(table: &str, ip: Ipv4Addr, port: u16) -> Result<u64> {
    parse_listen_inodes(table, ip, port)
        .into_iter()
        .next()
        .with_context(|| format!("no LISTEN socket for {ip}:{port}"))
}

pub fn parse_listen_inodes(table: &str, ip: Ipv4Addr, port: u16) -> Vec<u64> {
    let mut out = Vec::new();
    let want_port = format!("{port:04X}");
    let want_addr = format!("{:08X}", ip_to_proc_hex(ip));
    let mut lines = table.lines();
    if lines.next().is_none() {
        return out;
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
            out.push(inode);
        }
    }
    out
}

fn first_openable_inode<T>(
    inodes: &[u64],
    mut open: impl FnMut(u64) -> Result<T>,
) -> Result<(u64, T)> {
    let mut last = None;
    for inode in inodes {
        match open(*inode) {
            Ok(v) => return Ok((*inode, v)),
            Err(e) => last = Some(e),
        }
    }
    match last {
        Some(e) => Err(e),
        None => bail!("no matching LISTEN inode"),
    }
}

pub fn ip_to_proc_hex(ip: Ipv4Addr) -> u32 {
    let o = ip.octets();
    u32::from(o[0]) | u32::from(o[1]) << 8 | u32::from(o[2]) << 16 | u32::from(o[3]) << 24
}

fn open_socket_by_inode(inode: u64) -> Result<CapturedListen> {
    let want = format!("socket:[{inode}]");
    let mut last_err: Option<anyhow::Error> = None;
    let own_pid = std::process::id() as i32;
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
        // Loader-held dups of a dead worker stay LISTEN; they are not owners.
        if pid == own_pid {
            continue;
        }
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
            match capture_foreign_socket(pid, fd_num, inode) {
                Ok(f) => return Ok(f),
                Err(err) => last_err = Some(err),
            }
        }
    }
    if let Some(err) = last_err {
        return Err(err).context(format!("socket inode {inode} found but capture failed"));
    }
    bail!("socket inode {inode} not found under a non-loader /proc/*/fd")
}

/// `open(/proc/pid/fd/N)` returns ENXIO for sockets on some kernels; pidfd_getfd works (Linux ≥ 5.6).
fn capture_foreign_socket(pid: i32, fd: i32, inode: u64) -> Result<CapturedListen> {
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) };
    if pidfd < 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("pidfd_open({pid})"));
    }
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd as RawFd) };
    let sockfd = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd(), fd, 0u32) };
    if sockfd < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("pidfd_getfd(pid={pid} fd={fd})"));
    }
    Ok(CapturedListen {
        inode,
        fd: unsafe { OwnedFd::from_raw_fd(sockfd as RawFd) },
        owner_pid: pid,
        owner_pidfd: pidfd,
    })
}

/// A readable pidfd means that exact task exited. Poll error is treated as dead.
fn pidfd_exited(pidfd: &OwnedFd) -> bool {
    let mut pfd = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let rc = unsafe { libc::poll(&mut pfd, 1, 0) };
    rc != 0
}

fn process_has_inode(pid: i32, inode: u64) -> bool {
    let want = format!("socket:[{inode}]");
    let fd_dir = PathBuf::from("/proc").join(pid.to_string()).join("fd");
    let Ok(fds) = fs::read_dir(fd_dir) else {
        return false;
    };
    fds.flatten().any(|fdent| {
        fs::read_link(fdent.path())
            .map(|target| target.to_string_lossy() == want)
            .unwrap_or(false)
    })
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
    use std::net::TcpListener;
    use std::process::{Command, Stdio};

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

    #[test]
    fn reuseport_tries_next_inode_when_first_vanished() {
        let (inode, value) = first_openable_inode(&[1001, 1002], |inode| {
            if inode == 1001 {
                bail!("vanished")
            } else {
                Ok("live")
            }
        })
        .unwrap();
        assert_eq!((inode, value), (1002, "live"));
    }

    #[test]
    fn parses_all_reuseport_inodes() {
        let table = "sl local_address rem_address st tx rx tr tm retr uid timeout inode\n\
0: 0100007F:1F90 00000000:0000 0A 0:0 00:0 0 0 0 1001\n\
1: 0100007F:1F90 00000000:0000 0A 0:0 00:0 0 0 0 1002\n";
        assert_eq!(
            parse_listen_inodes(table, Ipv4Addr::LOCALHOST, 8080),
            vec![1001, 1002]
        );
    }

    #[test]
    fn non_listen_states_are_ignored() {
        let table = "sl local_address rem_address st tx rx tr tm retr uid timeout inode\n\
0: 0100007F:1F90 0100007F:9999 01 0:0 00:0 0 0 0 2001\n\
1: 0100007F:1F90 00000000:0000 0A 0:0 00:0 0 0 0 2002\n";
        assert_eq!(
            parse_listen_inodes(table, Ipv4Addr::LOCALHOST, 8080),
            vec![2002]
        );
    }

    #[test]
    fn a_real_listen_fd_reports_listening() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let held = dup_fd(&listener).unwrap();
        assert!(fd_is_listening(&held), "listening socket must be detected");

        let plain = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        assert!(plain >= 0);
        let plain = unsafe { OwnedFd::from_raw_fd(plain) };
        assert!(
            !fd_is_listening(&plain),
            "non-listening socket must be rejected"
        );
    }

    #[test]
    fn find_skips_this_process_as_owner() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let err = find_listen_socket_file("127.0.0.1", port)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("non-loader") || err.contains("no live LISTEN"),
            "loader must not treat its own listen dup as owner: {err}"
        );
        let _keep = listener;
    }

    #[test]
    fn pidfd_becomes_readable_after_child_exits() {
        let mut child = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sleep");
        let pid = child.id() as i32;
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) };
        assert!(pidfd >= 0, "pidfd_open");
        let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd as RawFd) };
        assert!(!pidfd_exited(&pidfd), "live child must not look exited");
        child.kill().unwrap();
        let _ = child.wait();
        assert!(pidfd_exited(&pidfd), "pidfd must report the exact task exited");
    }

    #[test]
    fn capture_then_kill_owner_fails_health() {
        let script = r#"
import socket, sys, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 0))
s.listen(1)
print(s.getsockname()[1], flush=True)
time.sleep(30)
"#;
        let mut child = match Command::new("python3")
            .arg("-c")
            .arg(script)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(err) => {
                eprintln!("skip capture_then_kill_owner_fails_health: no python3 ({err})");
                return;
            }
        };
        let mut stdout = child.stdout.take().expect("child stdout");
        let mut buf = String::new();
        use std::io::Read;
        let mut tmp = [0u8; 16];
        let n = stdout.read(&mut tmp).unwrap_or(0);
        buf.push_str(&String::from_utf8_lossy(&tmp[..n]));
        let port: u16 = buf
            .trim()
            .parse()
            .unwrap_or_else(|_| {
                let _ = child.kill();
                panic!("child did not print a port: {buf:?}");
            });
        let captured = match find_listen_socket_file("127.0.0.1", port) {
            Ok(c) => c,
            Err(err) => {
                let _ = child.kill();
                panic!("capture failed: {err:#}");
            }
        };
        assert_eq!(captured.owner_pid, child.id() as i32);
        assert!(captured.owner_still_owns_listener());
        assert!(fd_is_listening(&captured.fd));
        child.kill().unwrap();
        let _ = child.wait();
        assert!(
            !captured.owner_still_owns_listener(),
            "dead owner must fail pidfd health even if the loader dup still listens"
        );
        assert!(
            fd_is_listening(&captured.fd),
            "loader dup can remain SO_ACCEPTCONN after owner exit — that is why pidfd is required"
        );
        let _keep = captured;
    }

    #[test]
    fn is_pid_name_digits_only() {
        assert!(is_pid_name("1234"));
        assert!(!is_pid_name(""));
        assert!(!is_pid_name("self"));
    }
}
