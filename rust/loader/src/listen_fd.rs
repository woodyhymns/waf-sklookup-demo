//! Discover OpenResty LISTEN inodes via `/proc/net/tcp` or `/proc/net/tcp6` + `pidfd_getfd`.

use std::fs::{self, File};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd}; // OwnedFd held for SOCKMAP lifetime
use std::path::PathBuf;

use anyhow::{bail, Context, Result};

pub fn find_listen_socket_file(host: &str, port: u16) -> Result<OwnedFd> {
    let ip: IpAddr = host
        .parse()
        .with_context(|| format!("invalid host {host:?}"))?;
    let inodes = listen_inodes_for(ip, port)?;
    let (inode, captured) = first_openable_inode(&inodes, open_socket_by_inode)
        .with_context(|| format!("no live LISTEN socket for {ip}:{port}"))?;
    crate::log_msg(format_args!(
        "discovered listen socket inode={inode} owned by pid={} for {ip}:{port}",
        captured.owner_pid
    ));
    Ok(captured.fd)
}

/// A listen socket captured from the L7 engine, tagged with the inode it came
/// from so we can tell "same socket" from "new socket at the same address".
pub struct CapturedListen {
    pub inode: u64,
    /// Duplicated listen socket, held so the SOCKMAP entry remains valid while
    /// the worker is alive.
    pub fd: OwnedFd,
    /// The process that owned the original listen FD at capture time.
    pub owner_pid: i32,
    /// A stable process identity. PID numbers can be reused after a worker
    /// exits, so checking only `/proc/<pid>/fd` could mistakenly bless an
    /// unrelated new process that reused the same number.
    owner_pidfd: OwnedFd,
}

impl CapturedListen {
    /// True only while the *original worker* remains alive and still holds the
    /// exact listener inode. The loader's duplicate can keep a dead worker's
    /// socket in LISTEN state forever; SO_ACCEPTCONN alone is therefore not a
    /// liveness check.
    pub fn owner_still_owns_listener(&self) -> bool {
        !pidfd_exited(&self.owner_pidfd) && process_has_inode(self.owner_pid, self.inode)
    }
}

fn listen_inodes_for(ip: IpAddr, port: u16) -> Result<Vec<u64>> {
    match ip {
        IpAddr::V4(v4) => {
            let data = fs::read_to_string("/proc/net/tcp").context("read /proc/net/tcp")?;
            let mut inodes = parse_listen_inodes(&data, v4, port);
            if inodes.is_empty() {
                inodes = parse_listen_inodes(&data, Ipv4Addr::UNSPECIFIED, port);
            }
            Ok(inodes)
        }
        IpAddr::V6(v6) => {
            let data = fs::read_to_string("/proc/net/tcp6").context("read /proc/net/tcp6")?;
            let mut inodes = parse_listen_inodes_v6(&data, v6, port);
            if inodes.is_empty() {
                inodes = parse_listen_inodes_v6(&data, Ipv6Addr::UNSPECIFIED, port);
            }
            Ok(inodes)
        }
    }
}

/// Capture **every** LISTEN socket bound to `host:port`.
///
/// With `SO_REUSEPORT` each nginx worker owns its own listen socket on the same
/// address, so grabbing only the first one (the old behaviour) meant the whole
/// dataplane depended on a single worker: if that worker died, `bpf_sk_assign`
/// started returning -ESOCKTNOSUPPORT for every steered port even though N-1
/// healthy workers were still accepting on natively-bound ports. Capturing all
/// of them lets the BPF program shard across workers and lose only 1/N on a
/// single worker failure.
///
/// Sockets whose inode disappears between the `/proc/net/tcp` read and the
/// `pidfd_getfd` are skipped rather than failing the whole scan, because a
/// worker reload legitimately races with us here.
pub fn capture_all_listen_sockets(host: &str, port: u16) -> Result<Vec<CapturedListen>> {
    let ip: IpAddr = host
        .parse()
        .with_context(|| format!("invalid host {host:?}"))?;
    let inodes = listen_inodes_for(ip, port)?;
    if inodes.is_empty() {
        bail!("no LISTEN socket for {ip}:{port}");
    }
    let mut out = Vec::with_capacity(inodes.len());
    let mut errors = Vec::new();
    for inode in inodes {
        match open_socket_by_inode(inode) {
            Ok(captured) => out.push(captured),
            Err(err) => errors.push(format!("inode {inode}: {err:#}")),
        }
    }
    if out.is_empty() {
        bail!(
            "found {} LISTEN inode(s) for {ip}:{port} but none could be captured: {}",
            errors.len(),
            errors.join("; ")
        );
    }
    if !errors.is_empty() {
        crate::log_msg(format_args!(
            "captured {}/{} listen sockets for {ip}:{port} ({} skipped: {})",
            out.len(),
            out.len() + errors.len(),
            errors.len(),
            errors.join("; ")
        ));
    }
    Ok(out)
}

/// True when `inode` is still a LISTEN socket at `host:port`.
///
/// This is the health check the old `rescan_slot` was missing: it compared
/// inodes of two FDs it had just captured, which cannot detect that the socket
/// it is holding has stopped listening. A socket that survives as an FD but
/// left LISTEN state still fails `bpf_sk_assign` with -ESOCKTNOSUPPORT.
pub fn inode_still_listening(host: &str, port: u16, inode: u64) -> Result<bool> {
    let ip: IpAddr = host
        .parse()
        .with_context(|| format!("invalid host {host:?}"))?;
    Ok(listen_inodes_for(ip, port)?.contains(&inode))
}

/// Verify a held FD is a TCP socket in LISTEN state. This alone is not enough
/// to establish worker health: a loader-held duplicate can remain listening
/// after its original worker exits. Pair it with `CapturedListen::owner_still_owns_listener`.
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
    parse_listen_inodes_raw(table, &format!("{:08X}", ip_to_proc_hex(ip)), port)
}

/// Linux exposes IPv6 addresses in /proc/net/tcp6 as four native-endian u32
/// words. Reverse each 4-byte word, not the whole 16-byte address; reversing
/// all bytes happens to work for neither `::1` nor ordinary production VIPs.
pub fn ip6_to_proc_hex(ip: Ipv6Addr) -> String {
    let octets = ip.octets();
    let mut out = String::with_capacity(32);
    for word in octets.chunks_exact(4) {
        for byte in word.iter().rev() {
            use std::fmt::Write as _;
            let _ = write!(&mut out, "{byte:02X}");
        }
    }
    out
}

pub fn parse_listen_inodes_v6(table: &str, ip: Ipv6Addr, port: u16) -> Vec<u64> {
    parse_listen_inodes_raw(table, &ip6_to_proc_hex(ip), port)
}

fn parse_listen_inodes_raw(table: &str, want_addr: &str, port: u16) -> Vec<u64> {
    let mut out = Vec::new();
    let want_port = format!("{port:04X}");
    let mut lines = table.lines();
    if lines.next().is_none() {
        return out;
    }
    for line in lines {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 || fields[3] != "0A" {
            continue;
        }
        let Some((addr, port_hex)) = fields[1].split_once(':') else {
            continue;
        };
        if !port_hex.eq_ignore_ascii_case(&want_port) || !addr.eq_ignore_ascii_case(want_addr) {
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
        // A prior capture puts a duplicate of every worker socket in the
        // loader. If we inspect ourselves during a rescan, a dead worker's
        // duplicate looks valid and is re-registered forever. Only the L7
        // worker is an authoritative owner.
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

/// Capture a foreign socket and retain a pidfd for the original owner.
///
/// `open(/proc/pid/fd/N)` returns ENXIO for sockets on some kernels;
/// `pidfd_getfd` works on Linux ≥5.6. Keeping the pidfd is critical: an owned
/// duplicate holds a TCP listener alive after its worker dies, so `getsockopt`
/// keeps returning SO_ACCEPTCONN=1 and cannot distinguish the dead shard.
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

/// Polling a pidfd is race-free across PID reuse. A readable pidfd means its
/// exact task exited; a poll error is treated as unhealthy (fail safe, rescan).
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
    fn parses_ipv6_listeners_and_kernel_word_order() {
        let table = "sl local_address remote_address st tx rx tr tm retr uid timeout inode\n\
0: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 0:0 00:0 0 0 0 6001\n\
1: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 0:0 00:0 0 0 0 6002\n";
        assert_eq!(
            ip6_to_proc_hex(Ipv6Addr::LOCALHOST),
            "00000000000000000000000001000000"
        );
        assert_eq!(
            parse_listen_inodes_v6(table, Ipv6Addr::LOCALHOST, 8080),
            vec![6001]
        );
        assert_eq!(
            parse_listen_inodes_v6(table, Ipv6Addr::UNSPECIFIED, 8080),
            vec![6002]
        );
    }

    #[test]
    fn non_listen_states_are_ignored() {
        // 01 = ESTABLISHED. Registering an established socket in the sockmap
        // would make bpf_sk_assign fail with -ESOCKTNOSUPPORT.
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
        // Guards the health check itself: a bound-and-listening socket must be
        // recognised, and a plain connected/unbound socket must not.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
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
}
