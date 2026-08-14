//! Load either BPF object, attach `sk_lookup` to current netns, register SOCKMAP FDs.

use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, RawFd};
use std::path::Path;

use anyhow::{Context, Result};
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags, Object, ObjectBuilder, OpenObject};

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
) -> Result<(LoadedBpf<'obj>, libbpf_rs::Link)> {
    bump_memlock_rlimit();
    match implementation {
        BpfImpl::C => load_c(open_object),
        BpfImpl::Rust => load_rust(),
    }
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
                    .find(|m| m.name() == "open_ports")
                    .context("Rust BPF object missing map open_ports")?;
                let redir_socket = obj
                    .maps()
                    .find(|m| m.name() == "redir_socket")
                    .context("Rust BPF object missing map redir_socket")?;
                f(&open_ports, &redir_socket)
            }
        }
    }
}

fn load_c<'obj>(
    open_object: &'obj mut MaybeUninit<OpenObject>,
) -> Result<(LoadedBpf<'obj>, libbpf_rs::Link)> {
    let skel_builder = DispatchSkelBuilder::default();
    let open_skel = skel_builder.open(open_object).context("open BPF object")?;
    let skel = open_skel.load().map_err(|e| {
        anyhow::anyhow!("load BPF: {e}\n(hint: need root/CAP_BPF and kernel sk_lookup)")
    })?;
    pin::assert_open_ports_max_entries(&skel.maps.open_ports)?;

    let netns = std::fs::File::open("/proc/self/ns/net").context("open netns")?;
    let link = skel
        .progs
        .dispatch
        .attach_netns(netns.as_raw_fd())
        .context("attach sk_lookup")?;
    crate::log_msg(format_args!("sk_lookup attached to current netns"));
    Ok((LoadedBpf::C(skel), link))
}

fn load_rust<'obj>() -> Result<(LoadedBpf<'obj>, libbpf_rs::Link)> {
    let path = Path::new(env!("RUST_BPF_OBJECT_PATH"));
    if !path.is_file() {
        anyhow::bail!(
            "Rust BPF object is missing at {}. Build it with `make rust-bpf` (requires nightly Rust and the bpfel-unknown-none target)",
            path.display()
        );
    }
    let open = ObjectBuilder::default()
        .open_file(path)
        .with_context(|| format!("open Rust BPF object {}", path.display()))?;
    let obj = open.load().map_err(|e| {
        anyhow::anyhow!(
            "load Rust BPF object {}: {e}\n(hint: need root/CAP_BPF and kernel sk_lookup)",
            path.display()
        )
    })?;
    let open_ports = obj
        .maps()
        .find(|m| m.name() == "open_ports")
        .context("Rust BPF object missing map open_ports")?;
    pin::assert_open_ports_max_entries(&open_ports)?;
    let netns = std::fs::File::open("/proc/self/ns/net").context("open netns")?;
    let dispatch = obj
        .progs_mut()
        .find(|p| p.name() == "dispatch")
        .context("Rust BPF object missing program dispatch")?;
    let link = dispatch
        .attach_netns(netns.as_raw_fd())
        .context("attach Rust sk_lookup")?;
    crate::log_msg(format_args!("Rust sk_lookup attached to current netns"));
    Ok((LoadedBpf::Rust(obj), link))
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
    match pin::pin_maps(pin_dir, bpf) {
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
