//! Load either BPF object, attach `sk_lookup` to current netns, register SOCKMAP FDs.

use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, RawFd};
use std::path::Path;

use anyhow::{Context, Result};
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{Link, MapCore, MapFlags, Object, ObjectBuilder, OpenObject, Program};

use crate::cli::BpfImpl;
use crate::dispatch::{DispatchSkel, DispatchSkelBuilder};
use crate::pin::{self, REDIR_TLS};

pub fn bump_memlock_rlimit() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let _ = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
}

pub fn load_and_attach<'obj>(
    open_object: &'obj mut MaybeUninit<OpenObject>,
    implementation: BpfImpl,
    pin_dir: &Path,
) -> Result<LoadedBpf<'obj>> {
    bump_memlock_rlimit();
    let bpf = match implementation {
        BpfImpl::C => load_c(open_object, pin_dir)?,
        BpfImpl::Rust => load_rust(pin_dir)?,
    };
    attach_or_upgrade_sk_lookup(&bpf, pin_dir)?;
    Ok(bpf)
}

pub enum LoadedBpf<'obj> {
    C(DispatchSkel<'obj>),
    Rust(Object),
}

impl LoadedBpf<'_> {
    pub fn with_open_ports<R>(&self, f: impl FnOnce(&dyn MapCore) -> Result<R>) -> Result<R> {
        self.with_maps(|open_ports, _| f(open_ports))
    }

    pub fn with_maps<R>(
        &self,
        f: impl FnOnce(&dyn MapCore, &dyn MapCore) -> Result<R>,
    ) -> Result<R> {
        match self {
            Self::C(skel) => f(&skel.maps.open_ports, &skel.maps.redir_socket),
            Self::Rust(obj) => {
                let open_ports = obj
                    .maps()
                    .find(|m| m.name() == pin::OPEN_PORTS_MAP)
                    .context("Rust BPF object missing map open_ports")?;
                let redir_socket = obj
                    .maps()
                    .find(|m| m.name() == pin::REDIR_SOCKET_MAP)
                    .context("Rust BPF object missing map redir_socket")?;
                f(&open_ports, &redir_socket)
            }
        }
    }

    fn with_dispatch_prog<R>(
        &self,
        f: impl FnOnce(&Program<'_>) -> Result<R>,
    ) -> Result<R> {
        match self {
            Self::C(skel) => f(&skel.progs.dispatch),
            Self::Rust(obj) => {
                let dispatch = obj
                    .progs()
                    .find(|p| p.name() == "dispatch")
                    .context("Rust BPF object missing program dispatch")?;
                f(&dispatch)
            }
        }
    }

    fn attach_netns(&self, netns_fd: RawFd) -> Result<Link> {
        match self {
            Self::C(skel) => skel
                .progs
                .dispatch
                .attach_netns(netns_fd)
                .context("attach sk_lookup"),
            Self::Rust(obj) => {
                let dispatch = obj
                    .progs_mut()
                    .find(|p| p.name() == "dispatch")
                    .context("Rust BPF object missing program dispatch")?;
                dispatch
                    .attach_netns(netns_fd)
                    .context("attach Rust sk_lookup")
            }
        }
    }
}

fn reuse_pinned_maps_if_present(open: &mut libbpf_rs::OpenObject, pin_dir: &Path) -> Result<()> {
    for mut map in open.maps_mut() {
        let name = map.name().to_string_lossy();
        let path = match name.as_ref() {
            pin::OPEN_PORTS_MAP if pin::open_ports_path(pin_dir).exists() => {
                pin::open_ports_path(pin_dir)
            }
            pin::REDIR_SOCKET_MAP if pin::redir_socket_path(pin_dir).exists() => {
                pin::redir_socket_path(pin_dir)
            }
            _ => continue,
        };
        map.reuse_pinned_map(&path)
            .with_context(|| format!("reuse pinned map {}", path.display()))?;
        crate::log_msg(format_args!("reusing pinned map {}", path.display()));
    }
    Ok(())
}

fn load_c<'obj>(
    open_object: &'obj mut MaybeUninit<OpenObject>,
    pin_dir: &Path,
) -> Result<LoadedBpf<'obj>> {
    let skel_builder = DispatchSkelBuilder::default();
    let mut open_skel = skel_builder.open(open_object).context("open BPF object")?;
    if pin::open_ports_path(pin_dir).exists() {
        open_skel
            .maps
            .open_ports
            .reuse_pinned_map(pin::open_ports_path(pin_dir))
            .with_context(|| format!("reuse {}", pin::open_ports_path(pin_dir).display()))?;
        crate::log_msg(format_args!(
            "reusing pinned map {}",
            pin::open_ports_path(pin_dir).display()
        ));
    }
    if pin::redir_socket_path(pin_dir).exists() {
        open_skel
            .maps
            .redir_socket
            .reuse_pinned_map(pin::redir_socket_path(pin_dir))
            .with_context(|| format!("reuse {}", pin::redir_socket_path(pin_dir).display()))?;
        crate::log_msg(format_args!(
            "reusing pinned map {}",
            pin::redir_socket_path(pin_dir).display()
        ));
    }
    let skel = open_skel.load().map_err(|e| {
        anyhow::anyhow!("load BPF: {e}\n(hint: need root/CAP_BPF and kernel sk_lookup)")
    })?;
    pin::assert_open_ports_max_entries(&skel.maps.open_ports)?;
    Ok(LoadedBpf::C(skel))
}

fn load_rust<'obj>(pin_dir: &Path) -> Result<LoadedBpf<'obj>> {
    let path = Path::new(env!("RUST_BPF_OBJECT_PATH"));
    if !path.is_file() {
        anyhow::bail!(
            "Rust BPF object is missing at {}. Build it with `make rust-bpf` (requires nightly Rust and the bpfel-unknown-none target)",
            path.display()
        );
    }
    let mut open = ObjectBuilder::default()
        .open_file(path)
        .with_context(|| format!("open Rust BPF object {}", path.display()))?;
    reuse_pinned_maps_if_present(&mut open, pin_dir)?;
    let obj = open.load().map_err(|e| {
        anyhow::anyhow!(
            "load Rust BPF object {}: {e}\n(hint: need root/CAP_BPF and kernel sk_lookup)",
            path.display()
        )
    })?;
    let open_ports = obj
        .maps()
        .find(|m| m.name() == pin::OPEN_PORTS_MAP)
        .context("Rust BPF object missing map open_ports")?;
    pin::assert_open_ports_max_entries(&open_ports)?;
    Ok(LoadedBpf::Rust(obj))
}

fn attach_or_upgrade_sk_lookup(bpf: &LoadedBpf<'_>, pin_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(pin_dir)
        .with_context(|| format!("mkdir {}", pin_dir.display()))?;
    let link_path = pin::sk_lookup_link_path(pin_dir);
    if link_path.exists() {
        let mut link = Link::open(&link_path)
            .with_context(|| format!("open pinned sk_lookup link {}", link_path.display()))?;
        bpf.with_dispatch_prog(|prog| {
            link.update_prog(prog)
                .map_err(|e| anyhow::anyhow!("bpf_link_update: {e}"))
        })?;
        link.disconnect();
        crate::log_msg(format_args!(
            "sk_lookup bpf_link_update on pinned link {}",
            link_path.display()
        ));
        return Ok(());
    }

    let netns = std::fs::File::open("/proc/self/ns/net").context("open netns")?;
    let mut link = bpf.attach_netns(netns.as_raw_fd())?;
    link.pin(&link_path).with_context(|| {
        format!("pin sk_lookup link at {}", link_path.display())
    })?;
    link.disconnect();
    crate::log_msg(format_args!(
        "sk_lookup attached and pinned at {} (disconnected; survives loader exit)",
        link_path.display()
    ));
    Ok(())
}

pub fn register_listen_fd(redir: &(impl MapCore + ?Sized), fd: RawFd, slot: u32) -> Result<()> {
    if slot > REDIR_TLS {
        anyhow::bail!("sockmap slot {slot} out of range");
    }
    let key = slot.to_ne_bytes();
    let vsz = redir.value_size() as usize;
    let mut val = vec![0u8; vsz];
    let fd_bytes = (fd as u64).to_ne_bytes();
    let n = vsz.min(fd_bytes.len());
    val[..n].copy_from_slice(&fd_bytes[..n]);
    redir
        .update(&key, &val, MapFlags::ANY)
        .with_context(|| format!("sockmap put slot {slot}"))?;
    crate::log_msg(format_args!(
        "registered listening socket fd={fd} in redir_socket[{slot}]"
    ));
    Ok(())
}

pub fn open_steered_ports(
    open_ports: &(impl MapCore + ?Sized),
    ports: &[u16],
    slot: u8,
) -> Result<()> {
    for port in ports {
        let mut key = vec![0u8; open_ports.key_size() as usize];
        let b = port.to_ne_bytes();
        let n = key.len().min(b.len());
        key[..n].copy_from_slice(&b[..n]);
        let mut val = vec![0u8; open_ports.value_size() as usize];
        if !val.is_empty() {
            val[0] = slot;
        }
        open_ports
            .update(&key, &val, MapFlags::ANY)
            .with_context(|| format!("open_ports put {port}"))?;
        crate::log_msg(format_args!(
            "opened steered port {port} → redir_socket[{slot}] (no userspace bind on that port)"
        ));
    }
    Ok(())
}

pub fn pin_or_warn(bpf: &mut LoadedBpf<'_>, pin_dir: &Path, fatal: bool) -> Result<bool> {
    match pin::ensure_maps_pinned(pin_dir, bpf) {
        Ok(()) => {
            crate::log_msg(format_args!(
                "pinned maps under {} (open_ports, redir_socket)",
                pin_dir.display()
            ));
            Ok(true)
        }
        Err(err) if fatal => Err(err).context(format!(
            "pin maps at {} (M2/M3 need the pin)",
            pin_dir.display()
        )),
        Err(err) => {
            crate::log_msg(format_args!(
                "warning: pin maps at {}: {err:#} (close-port / bpftool map delete will not work)",
                pin_dir.display()
            ));
            Ok(false)
        }
    }
}
