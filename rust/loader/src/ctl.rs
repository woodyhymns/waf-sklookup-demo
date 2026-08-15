//! Second-process CLI: add / remove / list / bulk against pinned `open_ports`.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::{collections::{BTreeSet, HashMap}, fs};

use anyhow::{bail, Context, Result};
use libbpf_rs::{MapCore, MapFlags, MapHandle};

use crate::bulk::{
    bulk_delete_ports, bulk_put_ports, format_bulk_summary, format_remove_summary,
    load_pinned_open_ports,
};
use crate::cli::{parse_go_flags, ParsedFlags};
use crate::desired::{self, DesiredPorts, PortBinding};
use crate::pin::{self, DEFAULT_BULK_BATCH, DEFAULT_PIN_DIR, REDIR_PRIMARY, REDIR_TLS};
use crate::ports::{self, collect_bulk_ports, generate_fill_ports, parse_skip_set};

pub const CTL_USAGE: &str = "\
Product control plane is the Unix socket (`ctl` / /run/waf-sklookup/ctl.sock).
Root CLI escape hatch (pinned open_ports; no OpenResty reload):

  sudo ./waf-sklookup-loader add|open PORT|START-END -tenant TENANT -site SITE [-cert ID] [-policy ID]
  sudo ./waf-sklookup-loader remove|close PORT|START-END [-range A-B] [-file F] [-stdin]
  sudo ./waf-sklookup-loader list [-count]
  sudo ./waf-sklookup-loader load-ports -range START-END | -file ports.txt | -stdin -tenant TENANT -site SITE
  sudo ./waf-sklookup-loader close-ports -range START-END | -file ports.txt | -stdin
  sudo ./waf-sklookup-loader bulk open -range START-END -tenant TENANT -site SITE
  sudo ./waf-sklookup-loader bulk close -range START-END    # 30K/60K close
  sudo ./waf-sklookup-loader bulk fill -count N [-start 5000] -tenant TENANT -site SITE
  sudo ./waf-sklookup-loader fill -count N [-start 5000] -tenant TENANT -site SITE
  sudo ./waf-sklookup-loader reconcile|apply [-ports-file ports.conf] [-policy-file policy.conf]
  sudo ./waf-sklookup-loader apply-central [-from central/desired-state.json] [-ports-file ports.conf]
  sudo ./waf-sklookup-loader freeze [--close-all] [-freeze-file /run/waf-sklookup/frozen]
  sudo ./waf-sklookup-loader unfreeze [-freeze-file /run/waf-sklookup/frozen]
  sudo ./waf-sklookup-loader close-all [-pin-dir DIR]
  sudo ./waf-sklookup-loader rescan-listen [-target 127.0.0.1:8080] [-tls-target ADDR]
  sudo ./waf-sklookup-loader import-listens -tenant TENANT -site SITE [-nginx-conf PATH] [--dry-run]
  sudo ./waf-sklookup-loader check-overlap [-nginx-conf PATH] [-ports-file ports.conf]
  sudo ./waf-sklookup-loader retire-conf-listen PORT [-nginx-conf PATH]
  sudo ./waf-sklookup-loader status|metrics [-nginx-conf PATH] [-ports-file ports.conf]

Mutating commands update the desired file (default ports.conf) and the pinned map.
  Pass -no-file to edit the live map only (test/hygiene overlay; next reconcile restores the file).

M3 Test: M3_FULL_LADDER=1 ./scripts/m3-fill-ports.sh 30000
";

pub fn run_ctl(args: &[String]) -> Result<()> {
    if args.is_empty() {
        bail!("{}", CTL_USAGE.trim());
    }
    let mutation = matches!(args[0].as_str(), "add"|"open"|"remove"|"close"|"load-ports"|"close-ports"|"bulk"|"fill"|"reconcile"|"apply"|"apply-central"|"freeze"|"unfreeze"|"close-all"|"import-listens");
    let result = match args[0].as_str() {
        "add" | "open" => ctl_add(&args[1..]),
        "remove" | "close" => ctl_remove(&args[1..]),
        "list" | "dump" => ctl_list(&args[1..]),
        "load-ports" => ctl_bulk_add(&args[1..]),
        "close-ports" => ctl_bulk_remove(&args[1..]),
        "bulk" => ctl_bulk(&args[1..]),
        "fill" => ctl_bulk_fill(&args[1..]),
        "reconcile" => ctl_reconcile(&args[1..]),
        "apply" if flag_value(args, "from-central").is_some() => ctl_apply_central(&args[1..]),
        "apply" => ctl_reconcile(&args[1..]),
        "apply-central" => ctl_apply_central(&args[1..]),
        "freeze" => ctl_freeze(&args[1..]),
        "unfreeze" => ctl_unfreeze(&args[1..]),
        "close-all" => ctl_close_all(&args[1..]),
        "rescan-listen" => ctl_rescan_listen(&args[1..]),
        "import-listens" => ctl_import_listens(&args[1..]),
        "check-overlap" => ctl_check_overlap(&args[1..]),
        "retire-conf-listen" => ctl_retire_conf_listen(&args[1..]),
        "status" | "metrics" => ctl_status(&args[1..]),
        "help" => {
            eprint!("{CTL_USAGE}");
            Ok(())
        }
        other => bail!("unknown command {other:?}\n{CTL_USAGE}"),
    };
    if mutation {
        let cred = crate::sockctl::PeerCred { pid: std::process::id() as i32, uid: unsafe { libc::getuid() }, gid: unsafe { libc::getgid() } };
        let detail = if args.len() > 1 { args[1..].join(",") } else { "none".into() };
        let tenant = flag_value(args, "tenant").unwrap_or("");
        let site = flag_value(args, "site").unwrap_or("");
        eprintln!("{} audit uid={} gid={} pid={} op={} tenant={} site={} ports={} ok={}", crate::log_prefix(),
            cred.uid, cred.gid, cred.pid, args[0], tenant, site, detail, result.is_ok());
    }
    result
}

fn flag_value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    for (i, arg) in args.iter().enumerate() {
        if let Some(v) = arg.strip_prefix(&format!("--{name}=")).or_else(|| arg.strip_prefix(&format!("-{name}="))) { return Some(v); }
        if arg == &format!("-{name}") || arg == &format!("--{name}") { return args.get(i + 1).map(String::as_str); }
    }
    None
}

fn ctl_rescan_listen(args: &[String]) -> Result<()> {
    let flags = parse_go_flags(args, &["help"], &["pin-dir", "target", "tls-target"])?;
    if maybe_help(&flags) {
        eprint!("{CTL_USAGE}");
        return Ok(());
    }
    let path = pin::redir_socket_path(pin_dir_of(&flags));
    let map = MapHandle::from_pinned_path(&path)
        .with_context(|| format!("open pinned redir_socket {}", path.display()))?;
    let mut held = Vec::new();
    crate::openresty::rescan_held(
        &map,
        flags.get("target").unwrap_or("127.0.0.1:8080"),
        flags.get("tls-target").filter(|v| !v.is_empty()),
        &mut held,
    )?;
    println!("rescan-listen: refreshed live listen fd(s); open_ports unchanged");
    Ok(())
}

fn ctl_import_listens(args: &[String]) -> Result<()> {
    let flags = parse_go_flags(args, &["tls", "dry-run", "help"], &["nginx-conf", "tenant", "site", "cert", "policy", "ports-file", "policy-file", "freeze-file", "central-out", "metrics-file"])?;
    if maybe_help(&flags) { eprint!("{CTL_USAGE}"); return Ok(()); }
    let binding = binding_from_flags(&flags).map_err(|_| anyhow::anyhow!("import-listens requires -tenant and -site"))?;
    let conf = nginx_conf_of(&flags);
    let bytes = fs::read(&conf).with_context(|| format!("read nginx config {}", conf.display()))?;
    let text = std::str::from_utf8(&bytes).context("nginx config is not UTF-8")?;
    let parsed = crate::nginx_listen::parse_listen_ports(text);
    let ports = crate::nginx_listen::importable_listen_ports(text);
    let skipped: Vec<u16> = parsed.into_iter().filter(|p| !ports.contains(p)).collect();
    reject_frozen(&flags, "import-listens", &binding.tenant, &binding.site, &ports)?;
    if flags.bool_flag("dry-run") {
        println!("import-listens dry-run import={ports:?} skipped={skipped:?}");
        return Ok(());
    }
    let ports_file = ports_file_of(&flags);
    let policy_file = policy_file_of(&flags);
    let mut desired = desired_or_empty(&ports_file, &policy_file)?;
    for port in &ports { desired.insert(*port, binding.clone()); }
    let policy = crate::policy::load(&policy_file)?;
    crate::policy::validate(&desired, &policy)?;
    if ports.is_empty() { println!("import-listens: nothing importable; skipped={skipped:?}"); return Ok(()); }
    desired::write(&ports_file, &desired)?;
    if let Some(path) = flags.get("central-out") { crate::central::write(Path::new(path), &desired)?; }
    println!("import-listens imported={ports:?} skipped={skipped:?} desired-only (nginx unchanged)");
    Ok(())
}

fn ctl_check_overlap(args: &[String]) -> Result<()> {
    let flags = parse_go_flags(args, &["help"], &["nginx-conf", "ports-file", "policy-file", "pin-dir"])?;
    if maybe_help(&flags) { eprint!("{CTL_USAGE}"); return Ok(()); }
    let desired = desired_or_empty(&ports_file_of(&flags), &policy_file_of(&flags))?;
    let (map, _) = map_if_available(&pin_dir_of(&flags));
    let conflicts = overlap(&real_ports(&nginx_conf_of(&flags))?, &desired, &map, &[]);
    if conflicts.is_empty() { println!("overlap: none"); Ok(()) } else { bail!("overlapping ports: {conflicts:?}") }
}

fn ctl_retire_conf_listen(args: &[String]) -> Result<()> {
    let flags = parse_go_flags(args, &["help"], &["nginx-conf"])?;
    if maybe_help(&flags) { eprint!("{CTL_USAGE}"); return Ok(()); }
    let raw = flags.args.first().ok_or_else(|| anyhow::anyhow!("retire-conf-listen needs PORT"))?;
    let port: u16 = raw.parse().context("invalid port")?;
    let text = fs::read_to_string(nginx_conf_of(&flags))?;
    let mut found = false;
    for line in text.lines() {
        if crate::nginx_listen::parse_listen_ports(line).contains(&port) { println!("{line}"); found = true; }
    }
    if !found { println!("no nginx listen line found for port {port}"); }
    println!("edit nginx manually then reload");
    Ok(())
}

pub(crate) fn status_value(nginx_conf: &Path, ports_file: &Path, policy_file: &Path, pin_dir: &Path, freeze_file: &Path, metrics_file: &Path) -> Result<serde_json::Value> {
    let real = real_ports(nginx_conf)?;
    let desired = desired_or_empty(ports_file, policy_file)?;
    let (map, available) = map_if_available(pin_dir);
    let candidates: BTreeSet<u16> = desired.keys().copied().chain(map.keys().copied()).collect();
    let virtual_ports: Vec<u16> = candidates.difference(&real).copied().collect();
    let overlap_ports: Vec<u16> = candidates.intersection(&real).copied().collect();
    Ok(serde_json::json!({
        "real": real.iter().copied().collect::<Vec<_>>(), "virtual": virtual_ports,
        "overlap": overlap_ports, "frozen": freeze_file.exists(), "desired_count": desired.len(),
        "map_count": map.len(), "file_map_agree": available && desired.iter().all(|(p,b)| map.get(p) == Some(&b.slot)) && map.len() == desired.len(),
        "virtual_listen_count": candidates.difference(&real).count(), "real_listen_count": real.len(),
        "overlap_count": candidates.intersection(&real).count(), "apply_fail_total": crate::metrics::read(metrics_file)
    }))
}

fn ctl_status(args: &[String]) -> Result<()> {
    let flags = parse_go_flags(args, &["help"], &["nginx-conf", "ports-file", "policy-file", "pin-dir", "freeze-file", "metrics-file"])?;
    if maybe_help(&flags) { eprint!("{CTL_USAGE}"); return Ok(()); }
    println!("{}", serde_json::to_string(&status_value(&nginx_conf_of(&flags), &ports_file_of(&flags), &policy_file_of(&flags), &pin_dir_of(&flags), &freeze_file_of(&flags), &metrics_file_of(&flags))?)?);
    Ok(())
}

pub fn enforce_ladder(ports: &[u16], explicit: bool) -> Result<()> {
    if ports.len() > 10_000 && !explicit && std::env::var("M3_FULL_LADDER").as_deref() != Ok("1") {
        bail!("{} ports in one operation is disabled; set M3_FULL_LADDER=1 or use -full-ladder", ports.len());
    }
    Ok(())
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

fn ports_file_of(flags: &ParsedFlags) -> PathBuf {
    PathBuf::from(flags.get("ports-file").unwrap_or("ports.conf"))
}

fn policy_file_of(flags: &ParsedFlags) -> PathBuf {
    flags.get("policy-file").map(PathBuf::from).unwrap_or_else(|| crate::policy::default_path(&ports_file_of(flags)))
}

fn freeze_file_of(flags: &ParsedFlags) -> PathBuf {
    PathBuf::from(flags.get("freeze-file").unwrap_or(crate::freeze::DEFAULT_FREEZE_FILE))
}

fn nginx_conf_of(flags: &ParsedFlags) -> PathBuf {
    PathBuf::from(flags.get("nginx-conf").unwrap_or("openresty/nginx.conf"))
}

fn metrics_file_of(flags: &ParsedFlags) -> PathBuf {
    PathBuf::from(flags.get("metrics-file").unwrap_or(crate::metrics::DEFAULT_METRICS_FILE))
}

fn real_ports(path: &Path) -> Result<BTreeSet<u16>> {
    if !path.exists() { return Ok(crate::nginx_listen::inner_real_ports()); }
    let text = fs::read_to_string(path).with_context(|| format!("read nginx config {}", path.display()))?;
    Ok(crate::nginx_listen::real_listen_ports(&text))
}

fn overlap(real: &BTreeSet<u16>, desired: &DesiredPorts, map: &HashMap<u16, u8>, adding: &[u16]) -> Vec<u16> {
    let candidates: BTreeSet<u16> = desired.keys().copied().chain(map.keys().copied()).chain(adding.iter().copied()).collect();
    real.intersection(&candidates).copied().collect()
}

fn fail_on_overlap(real: &BTreeSet<u16>, desired: &DesiredPorts, map: &HashMap<u16, u8>, adding: &[u16]) -> Result<()> {
    let conflicts = overlap(real, desired, map, adding);
    if !conflicts.is_empty() { bail!("real/virtual listen overlap: {conflicts:?}"); }
    Ok(())
}

fn map_if_available(pin_dir: &Path) -> (HashMap<u16, u8>, bool) {
    load_pinned_open_ports(pin_dir).and_then(|m| desired::read_map(&m)).map(|m| (m, true)).unwrap_or_default()
}

fn reject_frozen(flags: &ParsedFlags, op: &str, tenant: &str, site: &str, ports: &[u16]) -> Result<()> {
    crate::freeze::reject_if_frozen(&freeze_file_of(flags), op, tenant, site, ports)
}

fn binding_from_flags(flags: &ParsedFlags) -> Result<PortBinding> {
    let tenant = flags.get("tenant").unwrap_or("");
    let site = flags.get("site").unwrap_or("");
    if tenant.is_empty() || site.is_empty() {
        bail!("open/add requires -tenant and -site (binding is mandatory; see docs/binding.md)");
    }
    Ok(PortBinding { slot: ctl_slot(flags.bool_flag("tls")), tenant: tenant.into(), site: site.into(), cert: flags.get("cert").map(str::to_owned), policy: flags.get("policy").map(str::to_owned) })
}

fn maybe_help(flags: &ParsedFlags) -> bool {
    flags.bool_flag("help")
}

fn ctl_add(args: &[String]) -> Result<()> {
    let flags = parse_go_flags(
        args,
        &["tls", "stdin", "help", "no-file", "full-ladder"],
        &["pin-dir", "ports-file", "policy-file", "freeze-file", "range", "file", "tenant", "site", "cert", "policy", "nginx-conf", "metrics-file"],
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
    enforce_ladder(&ports, flags.bool_flag("full-ladder"))?;
    let binding = binding_from_flags(&flags)?;
    reject_frozen(&flags, "add/open", &binding.tenant, &binding.site, &ports)?;
    apply_add(
        &pin_dir_of(&flags),
        &ports_file_of(&flags),
        &policy_file_of(&flags),
        &ports,
        &binding,
        DEFAULT_BULK_BATCH,
        true,
        ports.len() > 32,
        !flags.bool_flag("no-file"),
        &nginx_conf_of(&flags),
        &metrics_file_of(&flags),
    )
}

fn ctl_remove(args: &[String]) -> Result<()> {
    let flags = parse_go_flags(
        args,
        &["stdin", "help", "no-file", "full-ladder"],
        &["pin-dir", "ports-file", "policy-file", "range", "file"],
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
                bail!("close/remove needs PORT, START-END, -range, -file, or -stdin");
            }
            return Err(err);
        }
    };
    enforce_ladder(&ports, flags.bool_flag("full-ladder"))?;
    apply_remove(
        &pin_dir_of(&flags),
        &ports_file_of(&flags),
        &policy_file_of(&flags),
        &ports,
        DEFAULT_BULK_BATCH,
        true,
        ports.len() > 32,
        !flags.bool_flag("no-file"),
    )
}

fn ctl_list(args: &[String]) -> Result<()> {
    let flags = parse_go_flags(args, &["count", "json", "help"], &["pin-dir", "ports-file", "policy-file", "nginx-conf", "kind"])?;
    if maybe_help(&flags) {
        eprint!("{CTL_USAGE}");
        return Ok(());
    }
    if flags.get("kind") == Some("virtual") {
        let desired = desired_or_empty(&ports_file_of(&flags), &policy_file_of(&flags))?;
        let (map, _) = map_if_available(&pin_dir_of(&flags));
        let all: BTreeSet<u16> = desired.keys().copied().chain(map.keys().copied()).collect();
        let real = real_ports(&nginx_conf_of(&flags))?;
        let ports: Vec<u16> = all.difference(&real).copied().collect();
        if flags.bool_flag("json") { println!("{}", serde_json::json!({"kind":"virtual","ports":ports})); }
        else if flags.bool_flag("count") { println!("count={}", ports.len()); }
        else { for port in ports { println!("{port}"); } }
        return Ok(());
    }
    if flags.bool_flag("json") {
        let map = load_pinned_open_ports(&pin_dir_of(&flags))?;
        let mut ports: Vec<u16> = desired::read_map(&map)?.into_keys().collect(); ports.sort_unstable();
        println!("{}", serde_json::json!({"kind":flags.get("kind").unwrap_or("all"),"ports":ports})); return Ok(());
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
        &["tls", "stdin", "quiet", "help", "no-file", "full-ladder"],
        &["pin-dir", "ports-file", "policy-file", "freeze-file", "range", "file", "batch", "tenant", "site", "cert", "policy", "nginx-conf", "metrics-file"],
    )?;
    if maybe_help(&flags) {
        eprint!("{CTL_USAGE}");
        return Ok(());
    }
    let ports = collect_from_flags(&flags)?;
    enforce_ladder(&ports, flags.bool_flag("full-ladder"))?;
    let batch = parse_batch(flags.get("batch"))?;
    let binding = binding_from_flags(&flags)?;
    reject_frozen(&flags, "bulk open/add", &binding.tenant, &binding.site, &ports)?;
    apply_add(
        &pin_dir_of(&flags),
        &ports_file_of(&flags),
        &policy_file_of(&flags),
        &ports,
        &binding,
        batch,
        !flags.bool_flag("quiet"),
        true,
        !flags.bool_flag("no-file"),
        &nginx_conf_of(&flags),
        &metrics_file_of(&flags),
    )
}

fn ctl_bulk_remove(args: &[String]) -> Result<()> {
    let flags = parse_go_flags(
        args,
        &["stdin", "quiet", "help", "no-file", "full-ladder"],
        &["pin-dir", "ports-file", "policy-file", "freeze-file", "range", "file", "batch"],
    )?;
    if maybe_help(&flags) {
        eprint!("{CTL_USAGE}");
        return Ok(());
    }
    let ports = collect_from_flags(&flags)?;
    reject_frozen(&flags, "bulk close/remove", "", "", &ports)?;
    enforce_ladder(&ports, flags.bool_flag("full-ladder"))?;
    let batch = parse_batch(flags.get("batch"))?;
    apply_remove(
        &pin_dir_of(&flags),
        &ports_file_of(&flags),
        &policy_file_of(&flags),
        &ports,
        batch,
        !flags.bool_flag("quiet"),
        true,
        !flags.bool_flag("no-file"),
    )
}

fn ctl_bulk_fill(args: &[String]) -> Result<()> {
    let flags = parse_go_flags(
        args,
        &["tls", "quiet", "help", "no-file", "full-ladder"],
        &["pin-dir", "ports-file", "policy-file", "freeze-file", "count", "start", "skip", "batch", "tenant", "site", "cert", "policy", "nginx-conf", "metrics-file"],
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
    enforce_ladder(&ports, flags.bool_flag("full-ladder"))?;
    let batch = parse_batch(flags.get("batch"))?;
    let pin = pin_dir_of(&flags);
    eprint!(
        "M3 fill: count={count} start={start} skip={skip_raw:?} pin={} (no OpenResty reload)\n",
        pin.display()
    );
    let binding = binding_from_flags(&flags)?;
    reject_frozen(&flags, "bulk fill", &binding.tenant, &binding.site, &ports)?;
    apply_add(
        &pin,
        &ports_file_of(&flags),
        &policy_file_of(&flags),
        &ports,
        &binding,
        batch,
        !flags.bool_flag("quiet"),
        true,
        !flags.bool_flag("no-file"),
        &nginx_conf_of(&flags),
        &metrics_file_of(&flags),
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

pub(crate) fn apply_add(
    pin_dir: &Path,
    ports_file: &Path,
    policy_file: &Path,
    ports: &[u16],
    binding: &PortBinding,
    batch: usize,
    progress: bool,
    summary: bool,
    sync_file: bool,
    nginx_conf: &Path,
    metrics_file: &Path,
) -> Result<()> {
    let mut desired = desired_or_empty(ports_file, policy_file)?;
    let real = real_ports(nginx_conf)?;
    if let Err(err) = fail_on_overlap(&real, &desired, &HashMap::new(), ports) {
        crate::metrics::increment(metrics_file);
        return Err(err);
    }
    for port in ports { desired.insert(*port, binding.clone()); }
    let policy = crate::policy::load(policy_file)?;
    if let Err(err) = crate::policy::validate(&desired, &policy) { crate::metrics::increment(metrics_file); return Err(err); }
    let m = match load_pinned_open_ports(pin_dir) { Ok(m) => m, Err(err) => { crate::metrics::increment(metrics_file); return Err(err); } };
    let current = desired::read_map(&m)?;
    if let Err(err) = fail_on_overlap(&real, &desired, &current, &[]) { crate::metrics::increment(metrics_file); return Err(err); }
    if sync_file {
        desired::write(ports_file, &desired)?;
    }
    let mut stderr = io::stderr();
    let mut prog: Option<&mut dyn Write> = if progress { Some(&mut stderr) } else { None };
    let res = bulk_put_ports(&m, ports, binding.slot, batch, prog.as_deref_mut())?;
    if summary {
        println!("{}", format_bulk_summary("added", res.n, binding.slot, &res));
        return Ok(());
    }
    let label = if binding.slot == REDIR_TLS as u8 {
        " (stock TLS fallback)"
    } else {
        ""
    };
    for p in ports {
        println!("opened steered port {p} → redir_socket[{}]{label}", binding.slot);
    }
    Ok(())
}

pub(crate) fn apply_remove(
    pin_dir: &Path,
    ports_file: &Path,
    policy_file: &Path,
    ports: &[u16],
    batch: usize,
    progress: bool,
    summary: bool,
    sync_file: bool,
) -> Result<()> {
    let m = load_pinned_open_ports(pin_dir)?;
    if sync_file {
        let mut desired = desired::load_with_policy(ports_file, policy_file)?;
        for port in ports {
            desired.remove(port);
        }
        desired::write(ports_file, &desired)?;
    }
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

pub fn close_pinned_ports(pin_dir: &Path, ports_file: &Path, ports: &[u16]) -> Result<()> {
    apply_remove(pin_dir, ports_file, &crate::policy::default_path(ports_file), ports, DEFAULT_BULK_BATCH, false, false, true)
}

pub fn open_pinned_ports(
    pin_dir: &Path,
    ports_file: &Path,
    http_ports: &[u16],
    tls_ports: &[u16],
    binding: &PortBinding,
    policy_file: &Path,
) -> Result<()> {
    let overlap = ports::port_set_overlap(http_ports, tls_ports);
    if !overlap.is_empty() {
        bail!("port listed in both -ports and -tls-ports: {overlap:?}");
    }
    if !http_ports.is_empty() {
        apply_add(
            pin_dir,
            ports_file,
            policy_file, http_ports,
            &PortBinding { slot: REDIR_PRIMARY as u8, ..binding.clone() },
            DEFAULT_BULK_BATCH,
            false,
            false,
            true,
            Path::new("openresty/nginx.conf"),
            Path::new(crate::metrics::DEFAULT_METRICS_FILE),
        )?;
    }
    if !tls_ports.is_empty() {
        apply_add(
            pin_dir,
            ports_file,
            policy_file, tls_ports,
            &PortBinding { slot: REDIR_TLS as u8, ..binding.clone() },
            DEFAULT_BULK_BATCH,
            false,
            false,
            true,
            Path::new("openresty/nginx.conf"),
            Path::new(crate::metrics::DEFAULT_METRICS_FILE),
        )?;
    }
    Ok(())
}

fn desired_or_empty(path: &Path, policy_file: &Path) -> Result<DesiredPorts> {
    if path.exists() { desired::load_with_policy(path, policy_file) } else { Ok(DesiredPorts::new()) }
}

pub(crate) fn ctl_reconcile(args: &[String]) -> Result<()> {
    let flags = parse_go_flags(args, &["quiet", "help"], &["pin-dir", "ports-file", "policy-file", "freeze-file", "batch", "nginx-conf", "metrics-file"])?;
    if maybe_help(&flags) {
        eprint!("{CTL_USAGE}");
        return Ok(());
    }
    reject_frozen(&flags, "reconcile/apply", "", "", &[])?;
    let desired = desired::load_with_policy(&ports_file_of(&flags), &policy_file_of(&flags))?;
    let real = real_ports(&nginx_conf_of(&flags))?;
    if let Err(err) = fail_on_overlap(&real, &desired, &HashMap::new(), &[]) { crate::metrics::increment(&metrics_file_of(&flags)); return Err(err); }
    let map = match load_pinned_open_ports(&pin_dir_of(&flags)) { Ok(m) => m, Err(err) => { crate::metrics::increment(&metrics_file_of(&flags)); return Err(err); } };
    let current = desired::read_map(&map)?;
    if let Err(err) = fail_on_overlap(&real, &desired, &current, &[]) { crate::metrics::increment(&metrics_file_of(&flags)); return Err(err); }
    let plan = desired::plan(&desired, &current);
    let batch = parse_batch(flags.get("batch"))?;
    let mut stderr = io::stderr();
    let progress = !flags.bool_flag("quiet");
    if !plan.put_primary.is_empty() {
        bulk_put_ports(
            &map,
            &plan.put_primary,
            REDIR_PRIMARY as u8,
            batch,
            if progress { Some(&mut stderr) } else { None },
        )?;
    }
    if !plan.put_tls.is_empty() {
        bulk_put_ports(
            &map,
            &plan.put_tls,
            REDIR_TLS as u8,
            batch,
            if progress { Some(&mut stderr) } else { None },
        )?;
    }
    if !plan.delete.is_empty() {
        bulk_delete_ports(
            &map,
            &plan.delete,
            batch,
            if progress { Some(&mut stderr) } else { None },
        )?;
    }
    println!(
        "reconciled desired={} put={} delete={} file={}",
        desired.len(),
        plan.put_primary.len() + plan.put_tls.len(),
        plan.delete.len(),
        ports_file_of(&flags).display()
    );
    Ok(())
}

fn ctl_apply_central(args: &[String]) -> Result<()> {
    let flags = parse_go_flags(args, &["quiet", "help"], &["from", "from-central", "pin-dir", "ports-file", "policy-file", "freeze-file", "batch", "nginx-conf", "metrics-file"])?;
    if maybe_help(&flags) { eprint!("{CTL_USAGE}"); return Ok(()); }
    reject_frozen(&flags, "apply-central", "", "", &[])?;
    let source = flags.get("from").or_else(|| flags.get("from-central")).unwrap_or("central/desired-state.json");
    let incoming = crate::central::load(Path::new(source))?;
    crate::policy::validate(&incoming, &crate::policy::load(&policy_file_of(&flags))?)?;
    let real = real_ports(&nginx_conf_of(&flags))?;
    if let Err(err) = fail_on_overlap(&real, &incoming, &HashMap::new(), &[]) { crate::metrics::increment(&metrics_file_of(&flags)); return Err(err); }
    let (current, available) = map_if_available(&pin_dir_of(&flags));
    if available { if let Err(err) = fail_on_overlap(&real, &incoming, &current, &[]) { crate::metrics::increment(&metrics_file_of(&flags)); return Err(err); } }
    crate::central::apply_cache(Path::new(source), &ports_file_of(&flags), &policy_file_of(&flags))?;
    let mut reconcile = vec!["-pin-dir".into(), pin_dir_of(&flags).display().to_string(), "-ports-file".into(), ports_file_of(&flags).display().to_string(), "-policy-file".into(), policy_file_of(&flags).display().to_string(), "-freeze-file".into(), freeze_file_of(&flags).display().to_string()];
    if flags.bool_flag("quiet") { reconcile.push("-quiet".into()); }
    if let Some(batch) = flags.get("batch") { reconcile.extend(["-batch".into(), batch.into()]); }
    reconcile.extend(["-nginx-conf".into(), nginx_conf_of(&flags).display().to_string(), "-metrics-file".into(), metrics_file_of(&flags).display().to_string()]);
    ctl_reconcile(&reconcile)
}

fn ctl_close_all(args: &[String]) -> Result<()> {
    let flags = parse_go_flags(args, &["quiet", "help"], &["pin-dir", "batch"])?;
    if maybe_help(&flags) { eprint!("{CTL_USAGE}"); return Ok(()); }
    let map = load_pinned_open_ports(&pin_dir_of(&flags))?;
    let mut ports: Vec<u16> = desired::read_map(&map)?.into_keys().collect();
    ports.sort_unstable();
    let batch = parse_batch(flags.get("batch"))?;
    let mut stderr = io::stderr();
    let result = bulk_delete_ports(&map, &ports, batch, if flags.bool_flag("quiet") { None } else { Some(&mut stderr) })?;
    println!("close-all removed={} (ports.conf unchanged)", result.n);
    Ok(())
}

fn ctl_freeze(args: &[String]) -> Result<()> {
    let flags = parse_go_flags(args, &["close-all", "help", "quiet"], &["freeze-file", "pin-dir", "batch"])?;
    if maybe_help(&flags) { eprint!("{CTL_USAGE}"); return Ok(()); }
    let path = freeze_file_of(&flags);
    crate::freeze::set_frozen(&path)?;
    println!("machine frozen state={}", path.display());
    if flags.bool_flag("close-all") {
        let mut close = vec!["-pin-dir".into(), pin_dir_of(&flags).display().to_string()];
        if flags.bool_flag("quiet") { close.push("-quiet".into()); }
        if let Some(batch) = flags.get("batch") { close.extend(["-batch".into(), batch.into()]); }
        let result = ctl_close_all(&close);
        let cred = crate::sockctl::PeerCred { pid: std::process::id() as i32, uid: unsafe { libc::getuid() }, gid: unsafe { libc::getgid() } };
        eprintln!("{}", crate::sockctl::audit_line(cred, "close-all", "", "", &[], result.is_ok()));
        result?;
    }
    Ok(())
}

fn ctl_unfreeze(args: &[String]) -> Result<()> {
    let flags = parse_go_flags(args, &["help"], &["freeze-file"])?;
    if maybe_help(&flags) { eprint!("{CTL_USAGE}"); return Ok(()); }
    let path = freeze_file_of(&flags);
    crate::freeze::clear_frozen(&path)?;
    println!("machine unfrozen state={} (ports unchanged)", path.display());
    Ok(())
}

pub fn dump_pinned_ports(pin_dir: &Path) -> Result<()> {
    list_pinned_ports(pin_dir, false)
}

#[allow(dead_code)]
pub fn pin_max() -> u32 {
    pin::OPEN_PORTS_MAX_ENTRIES
}

#[cfg(test)]
mod tests {
    use super::*;
    fn strings(items: &[&str]) -> Vec<String> { items.iter().map(|s| (*s).into()).collect() }

    fn fixture() -> (PathBuf, PathBuf, PathBuf, PathBuf, PathBuf, PathBuf) {
        let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("waf-e8-{}-{n}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let ports = dir.join("ports.conf");
        let policy = dir.join("policy.conf");
        let nginx = dir.join("nginx.conf");
        let pin = dir.join("missing-pin");
        let metrics = dir.join("metrics");
        fs::write(&policy, "allow_privileged=\nmax_ports_per_tenant=32\nmax_ports_per_machine=128\n").unwrap();
        (dir, ports, policy, nginx, pin, metrics)
    }

    #[test]
    fn add_binding_flags_are_mandatory() {
        let empty = parse_go_flags(&[], &["tls"], &["tenant", "site", "cert", "policy"]).unwrap();
        let err = binding_from_flags(&empty).unwrap_err().to_string();
        assert!(err.contains("-tenant and -site"));

        let args = vec!["-tenant=acme".into(), "-site".into(), "www".into()];
        let flags = parse_go_flags(&args, &["tls"], &["tenant", "site", "cert", "policy"]).unwrap();
        let binding = binding_from_flags(&flags).unwrap();
        assert_eq!(binding.tenant, "acme");
        assert_eq!(binding.site, "www");
    }

    #[test]
    fn emergency_commands_parse() {
        assert!(parse_go_flags(&["--close-all".into(), "-freeze-file".into(), "/tmp/f".into()], &["close-all"], &["freeze-file"]).unwrap().bool_flag("close-all"));
        assert!(crate::cli::is_ctl_command("close-all"));
        assert!(crate::cli::is_ctl_command("apply-central"));
    }

    #[test]
    fn overlap_conflict_fail_closed_on_add() {
        let (_dir, ports, policy, nginx, pin, metrics) = fixture();
        fs::write(&ports, "# desired open_ports\n18082 acme www\n").unwrap();
        fs::write(&nginx, "listen 18081;\n").unwrap();
        let before = fs::read(&ports).unwrap();
        let binding = PortBinding { slot: REDIR_PRIMARY as u8, tenant:"acme".into(), site:"www".into(), cert:None, policy:None };
        let err = apply_add(&pin, &ports, &policy, &[18081], &binding, 16, false, false, true, &nginx, &metrics).unwrap_err();
        assert!(err.to_string().contains("overlap"));
        assert_eq!(fs::read(&ports).unwrap(), before);
        assert_eq!(crate::metrics::read(&metrics), 1);
    }

    #[test]
    fn overlap_conflict_fail_closed_on_apply_central_or_reconcile() {
        let (dir, ports, policy, nginx, pin, metrics) = fixture();
        fs::write(&nginx, "listen 18081;\n").unwrap();
        fs::write(&ports, "# desired open_ports\n18082 acme www\n").unwrap();
        let before = fs::read(&ports).unwrap();
        let central = dir.join("central.json");
        fs::write(&central, r#"{"version":1,"ports":[{"tenant":"acme","site":"www","port":18081}]}"#).unwrap();
        let args = strings(&["-from", central.to_str().unwrap(), "-ports-file", ports.to_str().unwrap(), "-policy-file", policy.to_str().unwrap(), "-nginx-conf", nginx.to_str().unwrap(), "-pin-dir", pin.to_str().unwrap(), "-metrics-file", metrics.to_str().unwrap()]);
        assert!(ctl_apply_central(&args).unwrap_err().to_string().contains("overlap"));
        assert_eq!(fs::read(&ports).unwrap(), before);
        fs::write(&ports, "# desired open_ports\n8080 acme www\n").unwrap();
        let overlap_before = fs::read(&ports).unwrap();
        let args = strings(&["-ports-file", ports.to_str().unwrap(), "-policy-file", policy.to_str().unwrap(), "-nginx-conf", nginx.to_str().unwrap(), "-pin-dir", pin.to_str().unwrap(), "-metrics-file", metrics.to_str().unwrap()]);
        assert!(ctl_reconcile(&args).unwrap_err().to_string().contains("overlap"));
        assert_eq!(fs::read(&ports).unwrap(), overlap_before);
    }

    #[test]
    fn import_excludes_80_443_and_never_modifies_nginx() {
        let (dir, ports, policy, nginx, _pin, _metrics) = fixture();
        fs::write(&nginx, "listen 80;\nlisten 443 ssl;\nlisten 19001;\n").unwrap();
        let before = fs::read(&nginx).unwrap();
        let args = strings(&["-nginx-conf", nginx.to_str().unwrap(), "-ports-file", ports.to_str().unwrap(), "-policy-file", policy.to_str().unwrap(), "-tenant", "acme", "-site", "www"]);
        ctl_import_listens(&args).unwrap();
        let desired = fs::read_to_string(&ports).unwrap();
        assert!(desired.contains("19001 acme www")); assert!(!desired.lines().any(|l| l.starts_with("80 ") || l.starts_with("443 ")));
        let dry_path = dir.join("dry.conf");
        let dry = strings(&["-dry-run", "-nginx-conf", nginx.to_str().unwrap(), "-ports-file", dry_path.to_str().unwrap(), "-tenant", "acme", "-site", "www"]);
        ctl_import_listens(&dry).unwrap();
        assert_eq!(fs::read(&nginx).unwrap(), before);
        assert!(!dry_path.exists());
    }

    #[test]
    fn freeze_rejects_import_without_writes() {
        let (dir, ports, policy, nginx, _pin, _metrics) = fixture();
        fs::write(&nginx, "listen 19001;\n").unwrap(); let before = fs::read(&nginx).unwrap();
        let frozen = dir.join("frozen"); fs::write(&frozen, "frozen\n").unwrap();
        let args = strings(&["-nginx-conf", nginx.to_str().unwrap(), "-ports-file", ports.to_str().unwrap(), "-policy-file", policy.to_str().unwrap(), "-freeze-file", frozen.to_str().unwrap(), "-tenant", "acme", "-site", "www"]);
        assert!(ctl_import_listens(&args).unwrap_err().to_string().contains("frozen"));
        assert!(!ports.exists()); assert_eq!(fs::read(&nginx).unwrap(), before);
    }

    #[test]
    fn virtual_status_distinguishes_real_and_desired() {
        let (dir, ports, policy, nginx, pin, metrics) = fixture();
        fs::write(&nginx, "listen 8080;\nlisten 8443 ssl;\n").unwrap();
        fs::write(&ports, "# desired open_ports\n18081 acme www\n").unwrap();
        let v = status_value(&nginx, &ports, &policy, &pin, &dir.join("frozen"), &metrics).unwrap();
        assert!(v["real"].as_array().unwrap().contains(&serde_json::json!(8080)));
        assert!(v["real"].as_array().unwrap().contains(&serde_json::json!(8443)));
        assert_eq!(v["virtual"], serde_json::json!([18081])); assert_eq!(v["overlap"], serde_json::json!([]));
        assert_eq!(v["map_count"], 0); assert_eq!(v["file_map_agree"], false);
        let real = real_ports(&nginx).unwrap();
        let virtuals: Vec<u16> = [8080, 18081].into_iter().filter(|p| !real.contains(p)).collect();
        assert_eq!(virtuals, vec![18081]);
    }
}
