//! Rust userspace loader. Hot path stays C BPF (`dispatch.bpf.c`).
//! This is the default loader and can be selected via `LOADER_BIN`.

mod bulk;
mod cli;
mod ctl;
mod desired;
mod listen_fd;
mod load;
mod openresty;
mod pin;
mod ports;
mod sockctl;
mod toy;

#[allow(clippy::wildcard_imports, dead_code, unused_imports, non_snake_case)]
mod dispatch {
    include!(concat!(env!("OUT_DIR"), "/dispatch.skel.rs"));
}

use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::{bail, Result};
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
            ctl::open_pinned_ports(&args.pin_dir, &args.ports_file, &http_ports, &tls_ports)
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

fn run_attached(open_object: &mut MaybeUninit<OpenObject>, args: LongRunningArgs) -> Result<()> {
    let (mut skel, _link) = load::load_and_attach(open_object)?;

    let desired = if args.ports_file.exists() {
        let state = desired::load(&args.ports_file)?;
        log_msg(format_args!(
            "loaded desired ports from {}",
            args.ports_file.display()
        ));
        state
    } else {
        let steered = ports::parse_port_list_allow_empty(&args.ports_raw)
            .map_err(|e| anyhow::anyhow!("bad -ports: {e:#}"))?;
        let tls = ports::parse_port_list_allow_empty(&args.tls_ports_raw)
            .map_err(|e| anyhow::anyhow!("bad -tls-ports: {e:#}"))?;
        let state = desired::from_lists(&steered, &tls)?;
        desired::write(&args.ports_file, &state)?;
        log_msg(format_args!(
            "seeded missing desired ports file {} from -ports/-tls-ports",
            args.ports_file.display()
        ));
        state
    };
    let steered: Vec<u16> = desired
        .iter()
        .filter_map(|(p, s)| (*s == pin::REDIR_PRIMARY as u8).then_some(*p))
        .collect();
    let tls_ports: Vec<u16> = desired
        .iter()
        .filter_map(|(p, s)| (*s == pin::REDIR_TLS as u8).then_some(*p))
        .collect();

    let pin_fatal = matches!(args.mode, RunMode::OpenResty);
    let pinned = load::pin_or_warn(&mut skel, &args.pin_dir, pin_fatal)?;
    let _unpin = pin::UnpinOnDrop(if pinned {
        Some(args.pin_dir.clone())
    } else {
        None
    });

    let shutdown = Arc::new(AtomicBool::new(false));
    let reload = Arc::new(AtomicBool::new(false));
    let mutations = Arc::new(std::sync::Mutex::new(()));
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&shutdown))?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&shutdown))?;
    signal_hook::flag::register(signal_hook::consts::SIGQUIT, Arc::clone(&shutdown))?;
    signal_hook::flag::register(signal_hook::consts::SIGHUP, Arc::clone(&reload))?;

    // Hold listen FDs so SOCKMAP entries stay valid (same as Go keeping *os.File).
    let mut _held_fds = Vec::new();
    match args.mode {
        RunMode::Toy => {
            let fd = toy::run_toy_mode(&skel, &args.listen, &steered, &shutdown)?;
            if !tls_ports.is_empty() {
                use std::os::fd::AsRawFd;
                load::register_listen_fd(
                    &skel.maps.redir_socket,
                    fd.as_raw_fd(),
                    pin::REDIR_TLS,
                )?;
                load::open_steered_ports(
                    &skel.maps.open_ports,
                    &tls_ports,
                    pin::REDIR_TLS as u8,
                )?;
                log_msg(format_args!(
                    "toy mode maps desired `tls` entries to its HTTP socket"
                ));
            }
            _held_fds.push(fd);
        }
        RunMode::OpenResty => {
            let fds = openresty::run_openresty_mode(
                &skel,
                &args.target,
                &steered,
                &args.tls_target,
                &tls_ports,
                args.wait,
                &shutdown,
            )?;
            _held_fds.extend(fds);
        }
        RunMode::ClosePort | RunMode::OpenPort | RunMode::DumpPorts => {
            unreachable!("attached path")
        }
    }

    let initial = desired::reconcile_map(&skel.maps.open_ports, &desired)?;
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

    while !shutdown.load(Ordering::SeqCst) {
        if reload.swap(false, Ordering::SeqCst) {
            let _guard = mutations.lock().map_err(|_| anyhow::anyhow!("mutation lock poisoned"))?;
            match desired::load(&args.ports_file)
                .and_then(|state| desired::reconcile_map(&skel.maps.open_ports, &state))
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
        thread::sleep(Duration::from_millis(200));
    }
    if matches!(args.mode, RunMode::OpenResty) {
        log_msg(format_args!(
            "shutting down loader (OpenResty keeps running)"
        ));
    }
    Ok(())
}
