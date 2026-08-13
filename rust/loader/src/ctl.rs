//! Second-process CLI: add / remove / list / bulk against pinned `open_ports`.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use libbpf_rs::{MapCore, MapFlags};

use crate::bulk::{
    bulk_delete_ports, bulk_put_ports, format_bulk_summary, format_remove_summary,
    load_pinned_open_ports,
};
use crate::cli::{parse_go_flags, ParsedFlags};
use crate::pin::{self, DEFAULT_BULK_BATCH, DEFAULT_PIN_DIR, REDIR_PRIMARY, REDIR_TLS};
use crate::ports::{self, collect_bulk_ports, generate_fill_ports, parse_skip_set};

pub const CTL_USAGE: &str = "\
M2 control plane (pinned open_ports; no OpenResty reload):

  sudo ./waf-sklookup-loader add|open PORT|START-END [-range A-B] [-file F] [-stdin]
  sudo ./waf-sklookup-loader remove|close PORT|START-END [-range A-B] [-file F] [-stdin]
  sudo ./waf-sklookup-loader list [-count]
  sudo ./waf-sklookup-loader load-ports -range START-END | -file ports.txt | -stdin
  sudo ./waf-sklookup-loader close-ports -range START-END | -file ports.txt | -stdin
  sudo ./waf-sklookup-loader bulk open  -range START-END    # 30K/60K open
  sudo ./waf-sklookup-loader bulk close -range START-END    # 30K/60K close
  sudo ./waf-sklookup-loader bulk fill -count 30000 [-start 5000]

M3 Test: LOADER_BIN=./rust/loader/target/release/waf-sklookup-loader ./scripts/m3-fill-ports.sh 30000
Go remains the default loader and rollback (./waf-sklookup-demo).
";

pub fn run_ctl(args: &[String]) -> Result<()> {
    if args.is_empty() {
        bail!("{}", CTL_USAGE.trim());
    }
    match args[0].as_str() {
        "add" | "open" => ctl_add(&args[1..]),
        "remove" | "close" => ctl_remove(&args[1..]),
        "list" | "dump" => ctl_list(&args[1..]),
        "load-ports" => ctl_bulk_add(&args[1..]),
        "close-ports" => ctl_bulk_remove(&args[1..]),
        "bulk" => ctl_bulk(&args[1..]),
        "help" => {
            eprint!("{CTL_USAGE}");
            Ok(())
        }
        other => bail!("unknown command {other:?}\n{CTL_USAGE}"),
    }
}

fn ctl_slot(tls: bool) -> u8 {
    if tls {
        REDIR_TLS as u8
    } else {
        REDIR_PRIMARY as u8
    }
}

fn pin_dir_of(flags: &ParsedFlags) -> PathBuf {
    PathBuf::from(flags.get("pin-dir").unwrap_or(DEFAULT_PIN_DIR))
}

fn maybe_help(flags: &ParsedFlags) -> bool {
    flags.bool_flag("help")
}

fn ctl_add(args: &[String]) -> Result<()> {
    let flags = parse_go_flags(
        args,
        &["tls", "stdin", "help"],
        &["pin-dir", "range", "file"],
    )?;
    if maybe_help(&flags) {
        eprint!("{CTL_USAGE}");
        return Ok(());
    }
    let ports = match collect_from_flags(&flags) {
        Ok(p) => p,
        Err(err) => {
            if flags.get("range").unwrap_or("").is_empty()
                && flags.get("file").unwrap_or("").is_empty()
                && !flags.bool_flag("stdin")
                && flags.args.is_empty()
            {
                bail!("open/add needs PORT, START-END, -range, -file, or -stdin");
            }
            return Err(err);
        }
    };
    apply_add(
        &pin_dir_of(&flags),
        &ports,
        ctl_slot(flags.bool_flag("tls")),
        DEFAULT_BULK_BATCH,
        true,
        ports.len() > 32,
    )
}

fn ctl_remove(args: &[String]) -> Result<()> {
    let flags = parse_go_flags(args, &["stdin", "help"], &["pin-dir", "range", "file"])?;
    if maybe_help(&flags) {
        eprint!("{CTL_USAGE}");
        return Ok(());
    }
    let ports = match collect_from_flags(&flags) {
        Ok(p) => p,
        Err(err) => {
            if flags.get("range").unwrap_or("").is_empty()
                && flags.get("file").unwrap_or("").is_empty()
                && !flags.bool_flag("stdin")
                && flags.args.is_empty()
            {
                bail!("close/remove needs PORT, START-END, -range, -file, or -stdin");
            }
            return Err(err);
        }
    };
    apply_remove(
        &pin_dir_of(&flags),
        &ports,
        DEFAULT_BULK_BATCH,
        true,
        ports.len() > 32,
    )
}

fn ctl_list(args: &[String]) -> Result<()> {
    let flags = parse_go_flags(args, &["count", "help"], &["pin-dir"])?;
    if maybe_help(&flags) {
        eprint!("{CTL_USAGE}");
        return Ok(());
    }
    list_pinned_ports(&pin_dir_of(&flags), flags.bool_flag("count"))
}

fn ctl_bulk(args: &[String]) -> Result<()> {
    if args.is_empty() {
        bail!("bulk needs open|add | close|remove | fill");
    }
    match args[0].as_str() {
        "add" | "open" => ctl_bulk_add(&args[1..]),
        "remove" | "close" => ctl_bulk_remove(&args[1..]),
        "fill" => ctl_bulk_fill(&args[1..]),
        other => bail!("unknown bulk command {other:?} (want open/add, close/remove, fill)"),
    }
}

fn ctl_bulk_add(args: &[String]) -> Result<()> {
    let flags = parse_go_flags(
        args,
        &["tls", "stdin", "quiet", "help"],
        &["pin-dir", "range", "file", "batch"],
    )?;
    if maybe_help(&flags) {
        eprint!("{CTL_USAGE}");
        return Ok(());
    }
    let ports = collect_from_flags(&flags)?;
    let batch = parse_batch(flags.get("batch"))?;
    apply_add(
        &pin_dir_of(&flags),
        &ports,
        ctl_slot(flags.bool_flag("tls")),
        batch,
        !flags.bool_flag("quiet"),
        true,
    )
}

fn ctl_bulk_remove(args: &[String]) -> Result<()> {
    let flags = parse_go_flags(
        args,
        &["stdin", "quiet", "help"],
        &["pin-dir", "range", "file", "batch"],
    )?;
    if maybe_help(&flags) {
        eprint!("{CTL_USAGE}");
        return Ok(());
    }
    let ports = collect_from_flags(&flags)?;
    let batch = parse_batch(flags.get("batch"))?;
    apply_remove(
        &pin_dir_of(&flags),
        &ports,
        batch,
        !flags.bool_flag("quiet"),
        true,
    )
}

fn ctl_bulk_fill(args: &[String]) -> Result<()> {
    let flags = parse_go_flags(
        args,
        &["tls", "quiet", "help"],
        &["pin-dir", "count", "start", "skip", "batch"],
    )?;
    if maybe_help(&flags) {
        eprint!("{CTL_USAGE}");
        return Ok(());
    }
    let start: u64 = flags
        .get("start")
        .unwrap_or("5000")
        .parse()
        .unwrap_or(u64::MAX);
    if start > 65535 {
        bail!("fill -start {start} out of range");
    }
    let count: usize = flags
        .get("count")
        .unwrap_or("0")
        .parse()
        .context("fill -count")?;
    let skip_raw = flags.get("skip").unwrap_or("8080,8443");
    let skip = parse_skip_set(skip_raw)?;
    let ports = generate_fill_ports(start as u16, count, &skip)?;
    let batch = parse_batch(flags.get("batch"))?;
    let pin = pin_dir_of(&flags);
    eprint!(
        "M3 fill: count={count} start={start} skip={skip_raw:?} pin={} (no OpenResty reload)\n",
        pin.display()
    );
    apply_add(
        &pin,
        &ports,
        ctl_slot(flags.bool_flag("tls")),
        batch,
        !flags.bool_flag("quiet"),
        true,
    )
}

fn parse_batch(raw: Option<&str>) -> Result<usize> {
    match raw {
        None => Ok(DEFAULT_BULK_BATCH),
        Some(s) => s.parse().context("bad -batch"),
    }
}

fn collect_from_flags(flags: &ParsedFlags) -> Result<Vec<u16>> {
    collect_bulk_ports(
        flags.get("range"),
        flags.get("file"),
        flags.bool_flag("stdin"),
        &flags.args,
    )
}

fn apply_add(
    pin_dir: &Path,
    ports: &[u16],
    slot: u8,
    batch: usize,
    progress: bool,
    summary: bool,
) -> Result<()> {
    let m = load_pinned_open_ports(pin_dir)?;
    let mut stderr = io::stderr();
    let mut prog: Option<&mut dyn Write> = if progress { Some(&mut stderr) } else { None };
    let res = bulk_put_ports(&m, ports, slot, batch, prog.as_deref_mut())?;
    if summary {
        println!("{}", format_bulk_summary("added", res.n, slot, &res));
        return Ok(());
    }
    let label = if slot == REDIR_TLS as u8 {
        " (stock TLS fallback)"
    } else {
        ""
    };
    for p in ports {
        println!("opened steered port {p} → redir_socket[{slot}]{label}");
    }
    Ok(())
}

fn apply_remove(
    pin_dir: &Path,
    ports: &[u16],
    batch: usize,
    progress: bool,
    summary: bool,
) -> Result<()> {
    let m = load_pinned_open_ports(pin_dir)?;
    let mut stderr = io::stderr();
    let mut prog: Option<&mut dyn Write> = if progress { Some(&mut stderr) } else { None };
    let res = bulk_delete_ports(&m, ports, batch, prog.as_deref_mut())?;
    if summary {
        println!("{}", format_remove_summary(&res));
        return Ok(());
    }
    for p in ports {
        println!("closed steered port {p} (removed from open_ports)");
    }
    if res.missing > 0 {
        eprintln!(
            "note: {} port(s) were already absent from the map",
            res.missing
        );
    }
    Ok(())
}

pub fn list_pinned_ports(pin_dir: &Path, count_only: bool) -> Result<()> {
    let m = load_pinned_open_ports(pin_dir)?;
    let mut n = 0usize;
    for key in m.keys() {
        n += 1;
        if count_only {
            continue;
        }
        let port = port_from_key(&key);
        let val = m.lookup(&key, MapFlags::ANY)?.unwrap_or_else(|| vec![0]);
        let slot = val.first().copied().unwrap_or(0);
        let label = if slot == REDIR_TLS as u8 {
            "tls-fallback"
        } else {
            "primary"
        };
        println!("{port}\tredir={slot}\t{label}");
    }
    if count_only {
        println!("count={n}");
    }
    Ok(())
}

fn port_from_key(key: &[u8]) -> u16 {
    if key.len() >= 2 {
        u16::from_ne_bytes([key[0], key[1]])
    } else if key.len() == 1 {
        u16::from(key[0])
    } else {
        0
    }
}

pub fn close_pinned_ports(pin_dir: &Path, ports: &[u16]) -> Result<()> {
    apply_remove(pin_dir, ports, DEFAULT_BULK_BATCH, false, false)
}

pub fn open_pinned_ports(pin_dir: &Path, http_ports: &[u16], tls_ports: &[u16]) -> Result<()> {
    let overlap = ports::port_set_overlap(http_ports, tls_ports);
    if !overlap.is_empty() {
        bail!("port listed in both -ports and -tls-ports: {overlap:?}");
    }
    if !http_ports.is_empty() {
        apply_add(
            pin_dir,
            http_ports,
            REDIR_PRIMARY as u8,
            DEFAULT_BULK_BATCH,
            false,
            false,
        )?;
    }
    if !tls_ports.is_empty() {
        apply_add(
            pin_dir,
            tls_ports,
            REDIR_TLS as u8,
            DEFAULT_BULK_BATCH,
            false,
            false,
        )?;
    }
    Ok(())
}

pub fn dump_pinned_ports(pin_dir: &Path) -> Result<()> {
    list_pinned_ports(pin_dir, false)
}

#[allow(dead_code)]
pub fn pin_max() -> u32 {
    pin::OPEN_PORTS_MAX_ENTRIES
}
