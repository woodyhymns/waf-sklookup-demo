//! Rust userspace loader. Hot path stays C BPF (`dispatch.bpf.c`).
//! This is the default loader and can be selected via `LOADER_BIN`.

mod bulk;
mod cli;
mod ctl;
mod listen_fd;
mod load;
mod openresty;
mod pin;
mod ports;
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
            ctl::close_pinned_ports(&args.pin_dir, &all)
        }
        RunMode::OpenPort => {
            if http_ports.is_empty() && tls_ports.is_empty() {
                bail!("open-port needs -ports and/or -tls-ports");
            }
            ctl::open_pinned_ports(&args.pin_dir, &http_ports, &tls_ports)
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

    let steered = ports::parse_port_list_allow_empty(&args.ports_raw)
        .map_err(|e| anyhow::anyhow!("bad -ports: {e:#}"))?;
    let tls_ports = ports::parse_port_list_allow_empty(&args.tls_ports_raw)
        .map_err(|e| anyhow::anyhow!("bad -tls-ports: {e:#}"))?;
    let overlap = ports::port_set_overlap(&steered, &tls_ports);
    if !overlap.is_empty() {
        bail!("port listed in both -ports and -tls-ports: {overlap:?}");
    }

    let pin_fatal = matches!(args.mode, RunMode::OpenResty);
    let pinned = load::pin_or_warn(&mut skel, &args.pin_dir, pin_fatal)?;
    let _unpin = pin::UnpinOnDrop(if pinned {
        Some(args.pin_dir.clone())
    } else {
        None
    });

    let shutdown = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&shutdown);
    ctrlc::set_handler(move || {
        flag.store(true, Ordering::SeqCst);
    })?;

    // Hold listen FDs so SOCKMAP entries stay valid (same as Go keeping *os.File).
    let mut _held_fds = Vec::new();
    match args.mode {
        RunMode::Toy => {
            if steered.is_empty() {
                bail!("toy mode needs -ports");
            }
            if !tls_ports.is_empty() {
                bail!("toy mode does not use -tls-ports (HTTP only)");
            }
            let fd = toy::run_toy_mode(&skel, &args.listen, &steered, &shutdown)?;
            _held_fds.push(fd);
        }
        RunMode::OpenResty => {
            if steered.is_empty() && tls_ports.is_empty() {
                bail!("openresty mode needs -ports and/or -tls-ports");
            }
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

    while !shutdown.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(200));
    }
    if matches!(args.mode, RunMode::OpenResty) {
        log_msg(format_args!(
            "shutting down loader (OpenResty keeps running)"
        ));
    }
    Ok(())
}
