//! Authenticated JSON-lines control plane over a Linux Unix-domain socket.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::bulk::load_pinned_open_ports;
use crate::pin::{DEFAULT_BULK_BATCH, REDIR_PRIMARY, REDIR_TLS};

pub const DEFAULT_CTL_SOCK: &str = "/run/waf-sklookup/ctl.sock";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerCred {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

pub fn authorize(cred: PeerCred, owner: u32, group: u32, mode: u32) -> Result<()> {
    if mode & 0o007 != 0 {
        bail!("socket too open");
    }
    if cred.uid == 0 || cred.uid == owner || cred.gid == group {
        return Ok(());
    }
    bail!("unauthorized")
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub op: String,
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub tls: bool,
    #[serde(default)]
    pub count_only: bool,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub count: Option<usize>,
    #[serde(default)]
    pub start: Option<u16>,
    #[serde(default)]
    pub skip: Option<String>,
    #[serde(default)]
    pub full_ladder: bool,
    #[serde(default)]
    pub tenant: String,
    #[serde(default)]
    pub site: String,
    #[serde(default)]
    pub cert: Option<String>,
    #[serde(default)]
    pub policy: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    /// Destination VIP for the operation. Absent means the IPv4 wildcard, which
    /// is what every request meant before multi-VIP keys existed.
    #[serde(default)]
    pub addr: Option<String>,
}

pub fn format_ports(ports: &[u16]) -> String {
    match ports {
        [] => "none".into(),
        [p] => p.to_string(),
        ps if ps.len() <= 16 => ps.iter().map(u16::to_string).collect::<Vec<_>>().join(","),
        ps => format!("count={}", ps.len()),
    }
}

pub fn audit_line(
    cred: PeerCred,
    op: &str,
    tenant: &str,
    site: &str,
    ports: &[u16],
    ok: bool,
) -> String {
    format!(
        "{} audit uid={} gid={} pid={} op={} tenant={} site={} ports={} ok={}",
        crate::log_prefix(),
        cred.uid,
        cred.gid,
        cred.pid,
        op,
        tenant,
        site,
        format_ports(ports),
        ok
    )
}

pub struct Server {
    path: PathBuf,
    join: Option<JoinHandle<()>>,
}
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
        let _ = fs::remove_file(&self.path);
    }
}

pub fn start(
    path: PathBuf,
    group: Option<u32>,
    pin_dir: PathBuf,
    ports_file: PathBuf,
    shutdown: Arc<AtomicBool>,
    mutations: Arc<Mutex<()>>,
) -> Result<Server> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent_existed = parent.exists();
    fs::create_dir_all(parent)
        .with_context(|| format!("create control socket directory {}", parent.display()))?;
    if !parent_existed {
        fs::set_permissions(parent, fs::Permissions::from_mode(0o750))?;
    }
    let listener = bind_listener(&path, group, true)?;
    let thread_path = path.clone();
    let join = thread::spawn(move || {
        let mut listener = listener;
        crate::log_msg(format_args!(
            "control socket listening path={} mode=0660",
            thread_path.display()
        ));
        while !shutdown.load(Ordering::SeqCst) {
            if !thread_path.exists() {
                match bind_listener(&thread_path, group, false) {
                    Ok(new_listener) => {
                        listener = new_listener;
                        crate::log_msg(format_args!(
                            "control socket path recreated: {}",
                            thread_path.display()
                        ));
                    }
                    Err(err) => crate::log_msg(format_args!(
                        "control socket recreate failed (will retry): {err:#}"
                    )),
                }
            }
            match listener.accept() {
                Ok((stream, _)) => handle(stream, &thread_path, &pin_dir, &ports_file, &mutations),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(50))
                }
                Err(e) => crate::log_msg(format_args!("control socket accept failed: {e}")),
            }
        }
    });
    Ok(Server {
        path,
        join: Some(join),
    })
}

fn bind_listener(path: &Path, group: Option<u32>, unlink_stale: bool) -> Result<UnixListener> {
    if unlink_stale && path.exists() {
        fs::remove_file(path).with_context(|| format!("unlink stale socket {}", path.display()))?;
    }
    let listener = UnixListener::bind(path)
        .with_context(|| format!("bind control socket {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o660))?;
    if let Some(gid) = group {
        let rc = unsafe {
            libc::chown(
                std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?.as_ptr(),
                u32::MAX,
                gid,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error()).context("chown control socket");
        }
    }
    listener.set_nonblocking(true)?;
    Ok(listener)
}

fn peer_cred(stream: &UnixStream) -> Result<PeerCred> {
    let mut u = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut u as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("SO_PEERCRED");
    }
    Ok(PeerCred {
        pid: u.pid,
        uid: u.uid,
        gid: u.gid,
    })
}

fn handle(
    mut stream: UnixStream,
    path: &Path,
    pin_dir: &Path,
    ports_file: &Path,
    mutations: &Mutex<()>,
) {
    let result = (|| -> Result<Value> {
        let cred = peer_cred(&stream)?;
        let meta = fs::metadata(path)?;
        authorize(cred, meta.uid(), meta.gid(), meta.mode())?;
        let mut line = String::new();
        BufReader::new(stream.try_clone()?).read_line(&mut line)?;
        if line.len() > 1_048_576 {
            bail!("request too large");
        }
        let req: Request = serde_json::from_str(line.trim()).context("invalid JSON request")?;
        execute(&req, cred, pin_dir, ports_file, mutations)
    })();
    let response = match result {
        Ok(v) => json!({"ok":true,"result":v}),
        Err(e) => json!({"ok":false,"error":format!("{e:#}")}),
    };
    let _ = writeln!(stream, "{}", response);
}

fn execute(
    req: &Request,
    cred: PeerCred,
    pin_dir: &Path,
    ports_file: &Path,
    mutations: &Mutex<()>,
) -> Result<Value> {
    let op = req.op.to_ascii_lowercase();
    if op == "status" || op == "metrics" {
        return crate::ctl::status_value(
            Path::new("openresty/nginx.conf"),
            ports_file,
            &crate::policy::default_path(ports_file),
            pin_dir,
            Path::new(crate::freeze::DEFAULT_FREEZE_FILE),
            Path::new(crate::metrics::DEFAULT_METRICS_FILE),
        );
    }
    if matches!(op.as_str(), "list" | "dump") {
        let map = load_pinned_open_ports(pin_dir)?;
        let mut ports: Vec<_> = crate::desired::read_map(&map)?.into_iter().collect();
        if req.kind.as_deref() == Some("virtual") {
            let real = if let Ok(text) = fs::read_to_string("openresty/nginx.conf") {
                crate::nginx_listen::real_listen_ports(&text)
            } else {
                crate::nginx_listen::inner_real_ports()
            };
            let policy_file = crate::policy::default_path(ports_file);
            if let Ok((policy, _)) = crate::reservation::effective_policy(&policy_file, pin_dir) {
                if let Ok(wanted) = crate::desired::load_with_effective_policy(ports_file, &policy)
                {
                    for (key, binding) in wanted {
                        if !ports.iter().any(|(k, _)| *k == key) {
                            // Desired-but-not-yet-programmed: report a single shard;
                            // the loader stamps the real count on next reconcile.
                            ports.push((key, crate::key::PortVal::new(binding.slot, 1)));
                        }
                    }
                }
            }
            // nginx.conf listens are port-scoped, so filter on the port alone.
            ports.retain(|(k, _)| !real.contains(&k.port));
        }
        ports.sort_unstable();
        return if req.count_only {
            Ok(json!({"count":ports.len()}))
        } else {
            // Objects rather than tuples: a VIP-scoped entry must be
            // unambiguous to whoever consumes this socket.
            let rows: Vec<Value> = ports
                .iter()
                .map(|(k, v)| {
                    json!({
                        "port": k.port,
                        "addr": k.dest.to_string(),
                        "group": v.group,
                        "shards": v.shards,
                    })
                })
                .collect();
            Ok(json!({"ports": rows}))
        };
    }
    let mut ports = req.ports.clone();
    let actual_op = if op == "bulk" {
        req.action.as_deref().unwrap_or("").to_ascii_lowercase()
    } else {
        op.clone()
    };
    if actual_op == "fill" {
        let skip = crate::ports::parse_skip_set(req.skip.as_deref().unwrap_or("8080,8443"))?;
        ports = crate::ports::generate_fill_ports(
            req.start.unwrap_or(5000),
            req.count.unwrap_or(0),
            &skip,
        )?;
    }
    if matches!(
        actual_op.as_str(),
        "add" | "open" | "fill" | "apply" | "reconcile" | "apply-central"
    ) || op == "bulk"
    {
        if let Err(err) = crate::freeze::reject_if_frozen(
            Path::new(crate::freeze::DEFAULT_FREEZE_FILE),
            if op == "bulk" { "bulk" } else { &actual_op },
            &req.tenant,
            &req.site,
            &ports,
        ) {
            eprintln!(
                "{}",
                audit_line(cred, &actual_op, &req.tenant, &req.site, &ports, false)
            );
            return Err(err);
        }
    }
    if let Err(err) = crate::ctl::enforce_ladder(&ports, req.full_ladder) {
        eprintln!(
            "{}",
            audit_line(cred, &actual_op, &req.tenant, &req.site, &ports, false)
        );
        return Err(err);
    }
    if ports.is_empty() && matches!(actual_op.as_str(), "add" | "open" | "remove" | "close") {
        eprintln!(
            "{}",
            audit_line(cred, &actual_op, &req.tenant, &req.site, &ports, false)
        );
        bail!("{actual_op} needs at least one port");
    }
    let res = {
        let _guard = mutations
            .lock()
            .map_err(|_| anyhow::anyhow!("mutation lock poisoned"))?;
        match actual_op.as_str() {
            "add" | "open" | "fill" => {
                if req.tenant.is_empty() || req.site.is_empty() {
                    bail!("open/add requires tenant and site (binding is mandatory; see docs/binding.md)");
                }
                let dest = match req.addr.as_deref().filter(|v| !v.is_empty()) {
                    Some(raw) => crate::key::Dest::parse(raw)?,
                    None => crate::key::Dest::AnyV4,
                };
                let binding = crate::desired::PortBinding {
                    slot: if req.tls {
                        REDIR_TLS as u8
                    } else {
                        REDIR_PRIMARY as u8
                    },
                    tenant: req.tenant.clone(),
                    site: req.site.clone(),
                    cert: req.cert.clone(),
                    policy: req.policy.clone(),
                    dest,
                };
                crate::ctl::apply_add(
                    pin_dir,
                    ports_file,
                    &crate::policy::default_path(ports_file),
                    &ports,
                    &binding,
                    DEFAULT_BULK_BATCH,
                    false,
                    true,
                    true,
                    Path::new("openresty/nginx.conf"),
                    Path::new(crate::metrics::DEFAULT_METRICS_FILE),
                )
            }
            "remove" | "close" => crate::ctl::apply_remove(
                pin_dir,
                ports_file,
                &crate::policy::default_path(ports_file),
                &ports,
                DEFAULT_BULK_BATCH,
                false,
                true,
                true,
            ),
            "reconcile" | "apply" => crate::ctl::ctl_reconcile(&[
                "-quiet".into(),
                "-pin-dir".into(),
                pin_dir.display().to_string(),
                "-ports-file".into(),
                ports_file.display().to_string(),
            ]),
            _ => bail!("unknown operation {:?}", req.op),
        }
    };
    eprintln!(
        "{}",
        audit_line(
            cred,
            &actual_op,
            &req.tenant,
            &req.site,
            &ports,
            res.is_ok()
        )
    );
    res?;
    Ok(json!({"op":actual_op,"count":ports.len()}))
}

/// Extract the transport-only `-sock` flag without attempting to parse the
/// operation-specific flags that follow `ctl add|bulk`. The previous generic
/// parser saw `-addr` while looking only for `-sock` and rejected valid multi-
/// VIP requests before request construction.
fn split_socket_flag(args: &[String]) -> Result<(Option<String>, Vec<String>)> {
    let mut socket = None;
    let mut rest = Vec::with_capacity(args.len());
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "-sock" || arg == "--sock" {
            i += 1;
            if i >= args.len() {
                bail!("flag needs an argument: -sock");
            }
            socket = Some(args[i].clone());
        } else if let Some(value) = arg
            .strip_prefix("-sock=")
            .or_else(|| arg.strip_prefix("--sock="))
        {
            socket = Some(value.to_owned());
        } else {
            rest.push(arg.clone());
        }
        i += 1;
    }
    Ok((socket, rest))
}

pub fn run_client(args: &[String]) -> Result<()> {
    let (configured_socket, command) = split_socket_flag(args)?;
    if command.is_empty() {
        bail!("ctl needs list|status|add|remove|reconcile|bulk");
    }
    let sock = configured_socket
        .unwrap_or_else(|| std::env::var("CTL_SOCK").unwrap_or_else(|_| DEFAULT_CTL_SOCK.into()));
    if sock.is_empty() {
        bail!("control socket is disabled (empty path)");
    }
    let cmd = &command;
    let mut req = Request {
        op: cmd[0].clone(),
        ports: Vec::new(),
        tls: false,
        count_only: false,
        action: None,
        count: None,
        start: None,
        skip: None,
        full_ladder: false,
        tenant: String::new(),
        site: String::new(),
        cert: None,
        policy: None,
        kind: None,
        addr: None,
    };
    let rest = if req.op == "bulk" {
        if cmd.len() < 2 {
            bail!("bulk needs open|close|fill");
        }
        req.action = Some(cmd[1].clone());
        &cmd[2..]
    } else {
        &cmd[1..]
    };
    let is_fill = req.action.as_deref() == Some("fill");
    let bools: &[&str] = if is_fill {
        &["tls", "full-ladder"]
    } else {
        &["tls", "count", "count-only", "full-ladder"]
    };
    let values: &[&str] = if is_fill {
        &[
            "count", "start", "skip", "tenant", "site", "cert", "policy", "addr",
        ]
    } else {
        &["tenant", "site", "cert", "policy", "kind", "addr"]
    };
    let pf = crate::cli::parse_go_flags(rest, bools, values)?;
    req.tls = pf.bool_flag("tls");
    req.count_only = pf.bool_flag("count") || pf.bool_flag("count-only");
    req.full_ladder = pf.bool_flag("full-ladder");
    req.count = pf.get("count").map(str::parse).transpose()?;
    req.start = pf.get("start").map(str::parse).transpose()?;
    req.skip = pf.get("skip").map(str::to_owned);
    req.tenant = pf.get("tenant").unwrap_or("").to_owned();
    req.site = pf.get("site").unwrap_or("").to_owned();
    req.cert = pf.get("cert").map(str::to_owned);
    req.policy = pf.get("policy").map(str::to_owned);
    req.kind = pf.get("kind").map(str::to_owned);
    req.addr = pf.get("addr").map(str::to_owned);
    for spec in &pf.args {
        req.ports
            .extend(crate::ports::parse_port_list_flexible(spec)?);
    }
    let mut stream =
        UnixStream::connect(&sock).with_context(|| format!("connect control socket {sock}"))?;
    writeln!(stream, "{}", serde_json::to_string(&req)?)?;
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line)?;
    println!("{}", line.trim());
    let v: Value = serde_json::from_str(&line)?;
    if v.get("ok") != Some(&Value::Bool(true)) {
        bail!("control request failed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    // SDD-002 / T-025: client transport flags must not consume or reject
    // business flags such as -addr before the request parser sees them.
    #[test]
    fn socket_flag_is_extracted_without_rejecting_business_flags() {
        let args = vec![
            "add".into(),
            "19104".into(),
            "-addr".into(),
            "127.0.0.2".into(),
            "-tenant".into(),
            "acme".into(),
            "-sock".into(),
            "/tmp/ctl.sock".into(),
        ];
        let (sock, rest) = split_socket_flag(&args).unwrap();
        assert_eq!(sock.as_deref(), Some("/tmp/ctl.sock"));
        assert_eq!(
            rest,
            vec!["add", "19104", "-addr", "127.0.0.2", "-tenant", "acme"]
        );
    }

    #[test]
    fn auth_matrix() {
        assert!(authorize(
            PeerCred {
                pid: 1,
                uid: 10,
                gid: 30
            },
            10,
            20,
            0o140660
        )
        .is_ok());
        assert!(authorize(
            PeerCred {
                pid: 1,
                uid: 30,
                gid: 20
            },
            10,
            20,
            0o140660
        )
        .is_ok());
        assert!(authorize(
            PeerCred {
                pid: 1,
                uid: 30,
                gid: 40
            },
            10,
            20,
            0o140660
        )
        .is_err());
        assert!(authorize(
            PeerCred {
                pid: 1,
                uid: 0,
                gid: 99
            },
            10,
            20,
            0o140660
        )
        .is_ok());
        assert!(authorize(
            PeerCred {
                pid: 1,
                uid: 10,
                gid: 20
            },
            10,
            20,
            0o140666
        )
        .unwrap_err()
        .to_string()
        .contains("too open"));
    }
    #[test]
    fn parses_json() {
        let r: Request = serde_json::from_str(
            r#"{"op":"add","ports":[8080,8443],"tls":true,"tenant":"acme","site":"www"}"#,
        )
        .unwrap();
        assert_eq!(r.ports, vec![8080, 8443]);
        assert!(r.tls);
        assert_eq!(r.tenant, "acme");
        assert!(
            r.addr.is_none(),
            "absent addr must stay absent, not default to a string"
        );
    }

    #[test]
    fn addr_is_optional_and_parsed_when_present() {
        // Old clients omit addr entirely; new ones may scope to a VIP.
        let r: Request = serde_json::from_str(
            r#"{"op":"add","ports":[18081],"tenant":"a","site":"w","addr":"10.0.0.7"}"#,
        )
        .unwrap();
        assert_eq!(r.addr.as_deref(), Some("10.0.0.7"));
        assert_eq!(
            crate::key::Dest::parse("10.0.0.7").unwrap(),
            crate::key::Dest::V4("10.0.0.7".parse().unwrap())
        );
    }
    #[test]
    fn ladder_rejects_10001() {
        assert!(crate::ctl::enforce_ladder(&vec![1; 10_001], false).is_err());
    }
    #[test]
    fn audit_has_identity_and_ports() {
        let s = audit_line(
            PeerCred {
                pid: 123,
                uid: 7,
                gid: 8,
            },
            "add",
            "acme",
            "www",
            &[18083],
            true,
        );
        assert!(
            s.contains("audit uid=7 gid=8 pid=123 op=add tenant=acme site=www ports=18083 ok=true")
        );
    }
}
