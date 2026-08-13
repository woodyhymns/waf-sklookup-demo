//! Load C BPF object, attach `sk_lookup` to current netns, register SOCKMAP FDs.

use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, RawFd};
use std::path::Path;

use anyhow::{Context, Result};
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags, OpenObject};

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
) -> Result<(DispatchSkel<'obj>, libbpf_rs::Link)> {
    bump_memlock_rlimit();
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
    Ok((skel, link))
}

pub fn register_listen_fd(redir: &impl MapCore, fd: RawFd, slot: u32) -> Result<()> {
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

pub fn open_steered_ports(open_ports: &impl MapCore, ports: &[u16], slot: u8) -> Result<()> {
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

pub fn pin_or_warn(skel: &mut DispatchSkel<'_>, pin_dir: &Path, fatal: bool) -> Result<bool> {
    match pin::pin_maps(pin_dir, skel) {
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
