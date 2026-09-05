//! Rust userspace loader. C BPF remains default; `-bpf rust` selects its Rust twin.
//! This is the default loader and can be selected via `LOADER_BIN`.

mod bulk;
mod central;
mod cli;
mod ctl;
mod desired;
mod freeze;
mod listen_fd;
mod load;
mod metrics;
mod nginx_listen;
mod openresty;
mod pin;
mod policy;
mod ports;
mod sockctl;
mod toy;
mod upgrade;

#[allow(clippy::wildcard_imports, dead_code, unused_imports, non_snake_case)]
mod dispatch {
    include!(concat!(env!("OUT_DIR"), "/dispatch.skel.rs"));
}

use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use libbpf_rs::OpenObject;

use cli::{LongRunningArgs, RunMode};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("ctl") {
        if let Err(err) = sockctl::run_client(&args[2..]) { fatal(&format!("{err:#}")); }
        return;
    }
    if args.len() > 1 && cli::is_ctl_command(&args[1]) {
        if let Err(err) = ctl::run_ctl(&args[1..]) {
            fatal(&format!("{err:#}"));
        }
        return;
    }
    let parsed = match cli::parse_long_running(&args[1..]) {
        Ok(v) => v,
        Err(err) => fatal(&format!("{err:#}")),
    };
    if let Err(err) = run_loader(parsed) {
        fatal(&format!("{err:#}"));
    }
}

fn fatal(msg: &str) -> ! {
    eprintln!("{} {msg}", log_prefix());
    std::process::exit(1);
}

pub(crate) fn log_prefix() -> String {
    let mut t: libc::time_t = 0;
    unsafe { libc::time(&mut t) };
    let mut tm = std::mem::MaybeUninit::<libc::tm>::uninit();
    unsafe { libc::localtime_r(&t, tm.as_mut_ptr()) };
    let tm = unsafe { tm.assume_init() };
    format!(
        "{:04}/{:02}/{:02} {:02}:{:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}

pub(crate) fn log_msg(args: std::fmt::Arguments<'_>) {
    eprintln!("{} {args}", log_prefix());
}

fn run_loader(args: LongRunningArgs) -> Result<()> {
    match args.mode {
        RunMode::ClosePort | RunMode::OpenPort | RunMode::DumpPorts => run_map_edit(args),
        RunMode::Toy | RunMode::OpenResty => {
            let mut open_object = MaybeUninit::<OpenObject>::uninit();
            run_attached(&mut open_object, args)
        }
    }
}

fn run_map_edit(args: LongRunningArgs) -> Result<()> {
    let (http_ports, tls_ports) = map_edit_port_lists(&args)?;
    match args.mode {
        RunMode::ClosePort => {
            if http_ports.is_empty() && tls_ports.is_empty() {
                bail!("close-port needs -ports and/or -tls-ports");
            }
            let mut all = http_ports;
            all.extend(tls_ports);
            ctl::close_pinned_ports(&args.pin_dir, &args.ports_file, &all)
        }
        RunMode::OpenPort => {
            if http_ports.is_empty() && tls_ports.is_empty() {
                bail!("open-port needs -ports and/or -tls-ports");
            }
            if args.tenant.is_empty() || args.site.is_empty() {
                bail!("open-port requires -tenant and -site (binding is mandatory; see docs/binding.md)");
            }
            let binding = desired::PortBinding { slot: pin::REDIR_PRIMARY as u8, tenant: args.tenant.clone(), site: args.site.clone(), cert: args.cert.clone(), policy: args.policy.clone() };
            let policy_file = args.policy_file.clone().unwrap_or_else(|| policy::default_path(&args.ports_file));
            ctl::open_pinned_ports(&args.pin_dir, &args.ports_file, &http_ports, &tls_ports, &binding, &policy_file)
        }
        RunMode::DumpPorts => ctl::dump_pinned_ports(&args.pin_dir),
        RunMode::Toy | RunMode::OpenResty => {
            unreachable!("map-edit path")
        }
    }
}

fn map_edit_port_lists(args: &LongRunningArgs) -> Result<(Vec<u16>, Vec<u16>)> {
    let http = if args.ports_set {
        ports::parse_port_list_allow_empty(&args.ports_raw)
            .map_err(|e| anyhow::anyhow!("bad -ports: {e:#}"))?
    } else {
        Vec::new()
    };
    let tls = if args.tls_ports_set {
        ports::parse_port_list_allow_empty(&args.tls_ports_raw)
            .map_err(|e| anyhow::anyhow!("bad -tls-ports: {e:#}"))?
    } else {
        Vec::new()
    };
    Ok((http, tls))
}

fn acquire_loader_lock() -> Result<std::fs::File> {
    use std::os::fd::AsRawFd;
    let lock_dir = std::path::Path::new("/run/waf-sklookup");
    std::fs::create_dir_all(lock_dir)
        .with_context(|| format!("create lock dir {}", lock_dir.display()))?;
    let path = lock_dir.join("loader.lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(&path)
        .with_context(|| format!("open {}", path.display()))?;
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        bail!(
            "another loader owns {}; refusing to load/attach/pin",
            path.display()
        );
    }
    log_msg(format_args!("exclusive loader lock acquired: {}", path.display()));
    Ok(file)
}

fn run_attached(open_object: &mut MaybeUninit<OpenObject>, args: LongRunningArgs) -> Result<()> {
    let _pin_lock = acquire_loader_lock()?;
    let policy_file = args.policy_file.clone().unwrap_or_else(|| policy::default_path(&args.ports_file));
    let desired = if args.ports_file.exists() {
        let state = desired::load_with_policy(&args.ports_file, &policy_file)?;
        log_msg(format_args!(
            "loaded desired ports from {}",
            args.ports_file.display()
        ));
        state
    } else {
        if args.tenant.is_empty() || args.site.is_empty() {
            bail!("missing desired file cannot be seeded without -tenant and -site (binding is mandatory; see docs/binding.md)");
        }
        let steered = ports::parse_port_list_allow_empty(&args.ports_raw)
            .map_err(|e| anyhow::anyhow!("bad -ports: {e:#}"))?;
        let tls = ports::parse_port_list_allow_empty(&args.tls_ports_raw)
            .map_err(|e| anyhow::anyhow!("bad -tls-ports: {e:#}"))?;
        let mut state = desired::from_lists(&steered, &tls, &args.tenant, &args.site)?;
        for binding in state.values_mut() {
            binding.cert.clone_from(&args.cert);
            binding.policy.clone_from(&args.policy);
        }
        policy::validate(&state, &policy::load(&policy_file)?)?;
        desired::write(&args.ports_file, &state)?;
        log_msg(format_args!(
            "seeded missing desired ports file {} from -ports/-tls-ports",
            args.ports_file.display()
        ));
        state
    };
    let mut bpf = load::load_and_attach(open_object, args.bpf_impl, &args.pin_dir)?;
    let steered: Vec<u16> = desired
        .iter()
        .filter_map(|(p, b)| (b.slot == pin::REDIR_PRIMARY as u8).then_some(*p))
        .collect();
    let tls_ports: Vec<u16> = desired
        .iter()
        .filter_map(|(p, b)| (b.slot == pin::REDIR_TLS as u8).then_some(*p))
        .collect();

    let pin_fatal = matches!(args.mode, RunMode::OpenResty);
    let _pinned = load::pin_or_warn(&mut bpf, &args.pin_dir, pin_fatal)?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let reload = Arc::new(AtomicBool::new(false));
    let rescan = Arc::new(AtomicBool::new(false));
    let mutations = Arc::new(std::sync::Mutex::new(()));
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&shutdown))?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&shutdown))?;
    signal_hook::flag::register(signal_hook::consts::SIGQUIT, Arc::clone(&shutdown))?;
    signal_hook::flag::register(signal_hook::consts::SIGHUP, Arc::clone(&reload))?;
    signal_hook::flag::register(signal_hook::consts::SIGUSR1, Arc::clone(&rescan))?;

    // Hold listen FDs so SOCKMAP entries stay valid (same as Go keeping *os.File).
    let mut held_fds = Vec::new();
    match args.mode {
        RunMode::Toy => {
            let fd = bpf.with_maps(|open_ports, redir_socket| {
                toy::run_toy_mode(open_ports, redir_socket, &args.listen, &steered, &shutdown)
            })?;
            if !tls_ports.is_empty() {
                use std::os::fd::AsRawFd;
                bpf.with_maps(|open_ports, redir_socket| {
                    load::register_listen_fd(redir_socket, fd.as_raw_fd(), pin::REDIR_TLS)?;
                    load::open_steered_ports(open_ports, &tls_ports, pin::REDIR_TLS as u8)
                })?;
                log_msg(format_args!(
                    "toy mode maps desired `tls` entries to its HTTP socket"
                ));
            }
            held_fds.push(fd);
        }
        RunMode::OpenResty => {
            let fds = bpf.with_maps(|open_ports, redir_socket| {
                openresty::run_openresty_mode(
                    open_ports, redir_socket, &args.target, &steered, &args.tls_target,
                    &tls_ports, args.wait, &shutdown,
                )
            })?;
            held_fds.extend(fds);
        }
        RunMode::ClosePort | RunMode::OpenPort | RunMode::DumpPorts => {
            unreachable!("attached path")
        }
    }

    let initial = bpf.with_open_ports(|map| desired::reconcile_map(map, &desired))?;
    log_msg(format_args!(
        "desired-state reconcile: put={} delete={} file={}",
        initial.put_primary.len() + initial.put_tls.len(),
        initial.delete.len(),
        args.ports_file.display()
    ));

    let _ctl_server = match args.ctl_sock.clone() {
        Some(path) => match sockctl::start(
            path.clone(),
            args.ctl_group,
            args.pin_dir.clone(),
            args.ports_file.clone(),
            Arc::clone(&shutdown),
            Arc::clone(&mutations),
        ) {
            Ok(server) => Some(server),
            Err(err) => {
                log_msg(format_args!(
                    "control socket disabled (could not bind {}): {err:#}",
                    path.display()
                ));
                None
            }
        },
        None => {
            log_msg(format_args!("control socket disabled"));
            None
        }
    };

    let mut next_rescan = std::time::Instant::now() + Duration::from_secs(2);
    while !shutdown.load(Ordering::SeqCst) {
        if reload.swap(false, Ordering::SeqCst) {
            let _guard = mutations.lock().map_err(|_| anyhow::anyhow!("mutation lock poisoned"))?;
            match desired::load_with_policy(&args.ports_file, &policy_file)
                .and_then(|state| bpf.with_open_ports(|map| desired::reconcile_map(map, &state)))
            {
                Ok(plan) => log_msg(format_args!(
                    "SIGHUP reconcile: put={} delete={} file={}",
                    plan.put_primary.len() + plan.put_tls.len(),
                    plan.delete.len(),
                    args.ports_file.display()
                )),
                Err(err) => log_msg(format_args!("SIGHUP reconcile failed: {err:#}")),
            }
        }
        if matches!(args.mode, RunMode::OpenResty)
            && (rescan.swap(false, Ordering::SeqCst) || std::time::Instant::now() >= next_rescan)
        {
            let tls = (!tls_ports.is_empty()).then_some(args.tls_target.as_str());
            match bpf.with_maps(|_open_ports, redir_socket| {
                openresty::rescan_held(redir_socket, &args.target, tls, &mut held_fds)
            }) {
                Ok(n) if n > 0 => log_msg(format_args!(
                    "listen rescan changed {n} slot(s); open_ports unchanged"
                )),
                Ok(_) => {}
                Err(err) => log_msg(format_args!("listen rescan failed (will retry): {err:#}")),
            }
            next_rescan = std::time::Instant::now() + Duration::from_secs(2);
        }
        thread::sleep(Duration::from_millis(200));
    }
    if matches!(args.mode, RunMode::OpenResty) {
        log_msg(format_args!(
            "shutting down loader (OpenResty keeps running)"
        ));
    }
    Ok(())
}
