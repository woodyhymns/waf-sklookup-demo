//! Load either BPF object, attach `sk_lookup` to current netns, register SOCKMAP FDs.

use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, RawFd};
use std::path::Path;

use anyhow::{Context, Result};
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags, Object, ObjectBuilder, OpenObject};

use crate::cli::BpfImpl;
use crate::dispatch::{DispatchSkel, DispatchSkelBuilder};
use crate::key::{PortKey, PortVal};
use crate::pin;

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

    /// Run `f` with a named map, whichever implementation is loaded.
    pub fn with_named_map<R>(
        &self,
        name: &str,
        f: impl FnOnce(&dyn MapCore) -> Result<R>,
    ) -> Result<R> {
        match self {
            Self::C(skel) => match name {
                pin::OPEN_PORTS_MAP => f(&skel.maps.open_ports),
                pin::REDIR_SOCKET_MAP => f(&skel.maps.redir_socket),
                pin::STATS_MAP => f(&skel.maps.stats),
                pin::ANOMALIES_MAP => f(&skel.maps.anomalies),
                pin::ANOMALY_GATE_MAP => f(&skel.maps.anomaly_gate),
                other => anyhow::bail!("unknown map {other}"),
            },
            Self::Rust(obj) => {
                let map = obj
                    .maps()
                    .find(|m| m.name() == name)
                    .with_context(|| format!("Rust BPF object missing map {name}"))?;
                f(&map)
            }
        }
    }

    pub fn pin_map(&mut self, name: &str, path: &Path) -> Result<()> {
        match self {
            Self::C(skel) => match name {
                pin::OPEN_PORTS_MAP => skel.maps.open_ports.pin(path).map_err(Into::into),
                pin::REDIR_SOCKET_MAP => skel.maps.redir_socket.pin(path).map_err(Into::into),
                pin::STATS_MAP => skel.maps.stats.pin(path).map_err(Into::into),
                pin::ANOMALIES_MAP => skel.maps.anomalies.pin(path).map_err(Into::into),
                pin::ANOMALY_GATE_MAP => skel.maps.anomaly_gate.pin(path).map_err(Into::into),
                other => anyhow::bail!("unknown map {other}"),
            },
            Self::Rust(obj) => {
                let mut map = obj
                    .maps_mut()
                    .find(|m| m.name() == name)
                    .with_context(|| format!("Rust BPF object missing map {name}"))?;
                map.pin(path).map_err(Into::into)
            }
        }
    }

    /// Pin the loaded dispatch program so a second-process control plane can
    /// read its *live* kernel tag. Map layout alone is insufficient: distinct
    /// dataplanes can retain the same key/value sizes.
    pub fn pin_program(&mut self, path: &Path) -> Result<()> {
        match self {
            Self::C(skel) => skel.progs.dispatch.pin(path).map_err(Into::into),
            Self::Rust(obj) => {
                let mut prog = obj
                    .progs_mut()
                    .find(|p| p.name() == "dispatch")
                    .context("Rust BPF object missing program dispatch")?;
                prog.pin(path).map_err(Into::into)
            }
        }
    }

    /// Kernel-assigned id and instruction tag of the `dispatch` program. The
    /// tag is what lets `ctl` refuse to mutate a dataplane it does not match.
    pub fn program_identity(&self) -> Result<crate::identity::ProgramIdentity> {
        let fd = match self {
            Self::C(skel) => skel.progs.dispatch.as_fd().as_raw_fd(),
            Self::Rust(obj) => {
                let prog = obj
                    .progs()
                    .find(|p| p.name() == "dispatch")
                    .context("Rust BPF object missing program dispatch")?;
                prog.as_fd().as_raw_fd()
            }
        };
        crate::identity::from_prog_fd(fd)
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
    pin::assert_open_ports_layout(&skel.maps.open_ports)?;
    pin::assert_redir_socket_layout(&skel.maps.redir_socket)?;

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
    {
        let open_ports = obj
            .maps()
            .find(|m| m.name() == pin::OPEN_PORTS_MAP)
            .context("Rust BPF object missing map open_ports")?;
        pin::assert_open_ports_layout(&open_ports)?;
        let redir = obj
            .maps()
            .find(|m| m.name() == pin::REDIR_SOCKET_MAP)
            .context("Rust BPF object missing map redir_socket")?;
        pin::assert_redir_socket_layout(&redir)?;
    }
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

/// Put a listen fd into `redir_socket` at (group, shard).
pub fn register_listen_fd_shard(
    redir: &(impl MapCore + ?Sized),
    fd: RawFd,
    group: u32,
    shard: u32,
) -> Result<()> {
    let slot = pin::shard_slot(group, shard)?;
    let key = slot.to_ne_bytes();
    let vsz = redir.value_size() as usize;
    let mut val = vec![0u8; vsz];
    let fd_bytes = (fd as u64).to_ne_bytes();
    let n = vsz.min(fd_bytes.len());
    val[..n].copy_from_slice(&fd_bytes[..n]);
    redir
        .update(&key, &val, MapFlags::ANY)
        .with_context(|| format!("sockmap put group {group} shard {shard} (slot {slot})"))?;
    crate::log_msg(format_args!(
        "registered listening socket fd={fd} in redir_socket[{slot}] (group {group}, shard {shard})"
    ));
    Ok(())
}

/// Remove one shard from `redir_socket`.
pub fn unregister_listen_shard(
    redir: &(impl MapCore + ?Sized),
    group: u32,
    shard: u32,
) -> Result<()> {
    let slot = pin::shard_slot(group, shard)?;
    match redir.delete(&slot.to_ne_bytes()) {
        Ok(()) => Ok(()),
        // Already empty is not an error: rescan is idempotent.
        Err(err) if err.kind() == libbpf_rs::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("sockmap delete slot {slot}")),
    }
}

/// Backwards-compatible helper: register a single fd as shard 0 of a group.
pub fn register_listen_fd(redir: &(impl MapCore + ?Sized), fd: RawFd, group: u32) -> Result<()> {
    register_listen_fd_shard(redir, fd, group, 0)
}

pub fn open_steered_ports(
    open_ports: &(impl MapCore + ?Sized),
    ports: &[u16],
    group: u8,
    shards: u8,
) -> Result<()> {
    for port in ports {
        let key = PortKey::wildcard_v4(*port).to_bytes();
        let val = PortVal::new(group, shards).to_bytes();
        open_ports
            .update(&key, &val, MapFlags::ANY)
            .with_context(|| format!("open_ports put {port}"))?;
        crate::log_msg(format_args!(
            "opened steered port {port} → redir group {group} ({shards} shard(s)); no userspace bind on that port"
        ));
    }
    Ok(())
}

pub fn pin_or_warn(
    bpf: &mut LoadedBpf<'_>,
    link: &mut libbpf_rs::Link,
    pin_dir: &Path,
    fatal: bool,
) -> Result<bool> {
    match pin::pin_all(pin_dir, bpf, link) {
        Ok(()) => {
            crate::log_msg(format_args!(
                "pinned BPF objects under {} (maps, dispatch program, netns link)",
                pin_dir.display()
            ));
            // Record program identity next to the pins so short-lived ctl
            // processes can detect a dataplane/binary mismatch.
            match bpf.program_identity() {
                Ok(id) => {
                    if let Err(err) = crate::identity::write(pin_dir, &id) {
                        crate::log_msg(format_args!("warning: record program identity: {err:#}"));
                    } else {
                        crate::log_msg(format_args!(
                            "dataplane identity: prog id={} tag={}",
                            id.id, id.tag
                        ));
                    }
                }
                Err(err) => {
                    crate::log_msg(format_args!("warning: read program identity: {err:#}"));
                }
            }
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
