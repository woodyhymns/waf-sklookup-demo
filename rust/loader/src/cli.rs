//! Go-style `-flag` / `--flag` parsing so scripts can swap `LOADER_BIN`.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpfImpl {
    C,
    Rust,
}

impl BpfImpl {
    fn parse(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "c" => Ok(Self::C),
            "rust" => Ok(Self::Rust),
            other => bail!("invalid -bpf value {other:?} (want c or rust)"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunMode {
    Toy,
    OpenResty,
    ClosePort,
    OpenPort,
    DumpPorts,
}

impl RunMode {
    fn parse(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "toy" => Ok(Self::Toy),
            "openresty" => Ok(Self::OpenResty),
            "close-port" => Ok(Self::ClosePort),
            "open-port" => Ok(Self::OpenPort),
            "dump-ports" => Ok(Self::DumpPorts),
            other => bail!(
                "unknown -mode {other:?} (want toy, openresty, close-port, open-port, dump-ports)"
            ),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LongRunningArgs {
    pub bpf_impl: BpfImpl,
    pub mode: RunMode,
    pub listen: String,
    pub target: String,
    pub ports_raw: String,
    pub ports_set: bool,
    pub tls_target: String,
    pub tls_ports_raw: String,
    pub tls_ports_set: bool,
    pub wait: Duration,
    /// OpenResty worker socket health reconciliation cadence. This bounds the
    /// temporary black-hole window after an unclean worker exit.
    pub rescan_interval: Duration,
    pub pin_dir: PathBuf,
    pub ports_file: PathBuf,
    pub policy_file: Option<PathBuf>,
    pub tenant: String,
    pub site: String,
    pub cert: Option<String>,
    pub policy: Option<String>,
    pub ctl_sock: Option<PathBuf>,
    pub ctl_group: Option<u32>,
    /// `host:port` for the read-only Prometheus exporter. None disables it.
    pub metrics_listen: Option<String>,
}

pub fn is_ctl_command(s: &str) -> bool {
    matches!(
        s,
        "add"
            | "open"
            | "remove"
            | "close"
            | "list"
            | "dump"
            | "bulk"
            | "fill"
            | "load-ports"
            | "close-ports"
            | "reconcile"
            | "apply"
            | "apply-central"
            | "freeze"
            | "unfreeze"
            | "close-all"
            | "rescan-listen"
            | "import-listens"
            | "import-listen"
            | "migrate"
            | "check-overlap"
            | "retire-conf-listen"
            | "status"
            | "metrics"
            | "help"
    )
}

#[derive(Debug, Default)]
pub struct ParsedFlags {
    pub present: HashSet<String>,
    pub values: HashMap<String, String>,
    pub args: Vec<String>,
}

impl ParsedFlags {
    pub fn flag_set(&self, name: &str) -> bool {
        self.present.contains(name)
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }

    pub fn bool_flag(&self, name: &str) -> bool {
        match self.get(name) {
            Some("false" | "0") => false,
            Some(_) => true,
            None => false,
        }
    }
}

/// Parse Go-style argv (`-name value`, `--name=value`). Bool flags take no
/// value unless given as `-name=true`.
///
/// Unlike the standard Go `flag` package, flags may appear after positional
/// ports. The public CLI documents `add PORT -tenant ...`, and treating
/// `-tenant` as a second port made the documented dynamic-port operation fail
/// before reaching the BPF map. `--` remains the explicit end-of-flags marker.
pub fn parse_go_flags(
    argv: &[String],
    bool_flags: &[&str],
    value_flags: &[&str],
) -> Result<ParsedFlags> {
    let bool_set: HashSet<&str> = bool_flags.iter().copied().collect();
    let value_set: HashSet<&str> = value_flags.iter().copied().collect();
    let mut out = ParsedFlags::default();
    let mut i = 0;
    while i < argv.len() {
        let a = &argv[i];
        if a == "--" {
            out.args.extend(argv[i + 1..].iter().cloned());
            break;
        }
        if a == "-" || !a.starts_with('-') {
            // Keep parsing: control commands are intentionally documented as
            // `add PORT -tenant TENANT -site SITE`, not flags-first only.
            out.args.push(a.clone());
            i += 1;
            continue;
        }
        let (name, inline) = split_flag(a)?;
        if name == "h" || name == "help" {
            out.present.insert("help".into());
            out.values.insert("help".into(), "true".into());
            i += 1;
            continue;
        }
        if bool_set.contains(name.as_str()) {
            let val = match inline {
                Some(v) => v,
                None => "true".to_string(),
            };
            out.present.insert(name.clone());
            out.values.insert(name, val);
            i += 1;
            continue;
        }
        if value_set.contains(name.as_str()) {
            let val = match inline {
                Some(v) => v,
                None => {
                    i += 1;
                    if i >= argv.len() {
                        bail!("flag needs an argument: -{name}");
                    }
                    argv[i].clone()
                }
            };
            out.present.insert(name.clone());
            out.values.insert(name, val);
            i += 1;
            continue;
        }
        bail!("flag provided but not defined: -{name}");
    }
    Ok(out)
}

fn split_flag(a: &str) -> Result<(String, Option<String>)> {
    let rest = if let Some(r) = a.strip_prefix("--") {
        r
    } else if let Some(r) = a.strip_prefix('-') {
        r
    } else {
        bail!("not a flag: {a}");
    };
    if rest.is_empty() {
        bail!("empty flag");
    }
    if let Some((n, v)) = rest.split_once('=') {
        Ok((n.to_string(), Some(v.to_string())))
    } else {
        Ok((rest.to_string(), None))
    }
}

pub fn parse_long_running(argv: &[String]) -> Result<LongRunningArgs> {
    let flags = parse_go_flags(
        argv,
        &["help", "h", "no-ctl", "no-metrics"],
        &[
            "mode",
            "listen",
            "target",
            "ports",
            "tls-target",
            "tls-ports",
            "wait",
            "rescan-interval",
            "pin-dir",
            "ports-file",
            "policy-file",
            "tenant",
            "site",
            "cert",
            "policy",
            "ctl-sock",
            "ctl-group",
            "metrics-listen",
            "bpf",
        ],
    )?;
    if flags.bool_flag("help") {
        print_long_running_usage();
        std::process::exit(0);
    }
    let mode = RunMode::parse(flags.get("mode").unwrap_or("toy"))?;
    let bpf_raw = flags
        .get("bpf")
        .map(str::to_owned)
        .or_else(|| std::env::var("BPF_IMPL").ok())
        .unwrap_or_else(|| "c".into());
    let wait_raw = flags.get("wait").unwrap_or("60s");
    let rescan_raw = flags
        .get("rescan-interval")
        .map(str::to_owned)
        .unwrap_or_else(|| std::env::var("RESCAN_INTERVAL").unwrap_or_else(|_| "500ms".into()));
    let rescan_interval = parse_duration(&rescan_raw)
        .with_context(|| format!("bad -rescan-interval {rescan_raw:?}"))?;
    if rescan_interval < Duration::from_millis(100) {
        bail!("-rescan-interval must be at least 100ms (got {rescan_raw:?})");
    }
    if rescan_interval > Duration::from_secs(60) {
        bail!("-rescan-interval must not exceed 60s (got {rescan_raw:?})");
    }
    let ctl_raw = flags.get("ctl-sock").map(str::to_owned).unwrap_or_else(|| {
        std::env::var("CTL_SOCK").unwrap_or_else(|_| crate::sockctl::DEFAULT_CTL_SOCK.into())
    });
    let ctl_group = flags
        .get("ctl-group")
        .map(str::parse)
        .transpose()
        .context("bad -ctl-group (numeric gid required)")?;
    // Loopback by default: the exporter lives in a CAP_BPF process, so it must
    // not be reachable off-box unless an operator explicitly asks for it.
    let metrics_raw = flags
        .get("metrics-listen")
        .map(str::to_owned)
        .unwrap_or_else(|| {
            std::env::var("METRICS_LISTEN").unwrap_or_else(|_| "127.0.0.1:9101".into())
        });
    Ok(LongRunningArgs {
        bpf_impl: BpfImpl::parse(&bpf_raw)?,
        mode,
        listen: flags.get("listen").unwrap_or("127.0.0.1:18080").to_string(),
        target: flags.get("target").unwrap_or("127.0.0.1:8080").to_string(),
        ports_raw: flags
            .get("ports")
            .unwrap_or("18081,18082,65500")
            .to_string(),
        ports_set: flags.flag_set("ports"),
        tls_target: flags
            .get("tls-target")
            .unwrap_or("127.0.0.1:8443")
            .to_string(),
        tls_ports_raw: flags.get("tls-ports").unwrap_or("").to_string(),
        tls_ports_set: flags.flag_set("tls-ports"),
        wait: parse_duration(wait_raw).with_context(|| format!("bad -wait {wait_raw:?}"))?,
        rescan_interval,
        pin_dir: PathBuf::from(flags.get("pin-dir").unwrap_or(crate::pin::DEFAULT_PIN_DIR)),
        ports_file: PathBuf::from(flags.get("ports-file").unwrap_or("ports.conf")),
        policy_file: flags.get("policy-file").map(PathBuf::from),
        tenant: flags.get("tenant").unwrap_or("").to_string(),
        site: flags.get("site").unwrap_or("").to_string(),
        cert: flags.get("cert").map(str::to_owned),
        policy: flags.get("policy").map(str::to_owned),
        ctl_sock: (!flags.bool_flag("no-ctl") && !ctl_raw.is_empty())
            .then(|| PathBuf::from(ctl_raw)),
        ctl_group,
        metrics_listen: (!flags.bool_flag("no-metrics") && !metrics_raw.is_empty())
            .then_some(metrics_raw),
    })
}

/// Go `time.ParseDuration` subset used by the demo (`60s`, `1m`, `500ms`, combined).
pub fn parse_duration(raw: &str) -> Result<Duration> {
    let s = raw.trim();
    if s.is_empty() {
        bail!("empty duration");
    }
    if s == "0" || s == "0s" {
        return Ok(Duration::ZERO);
    }
    let mut total = Duration::ZERO;
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let start = i;
        if bytes[i] == b'.' || bytes[i].is_ascii_digit() {
            i += 1;
            while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
                i += 1;
            }
        } else {
            bail!("bad duration {raw:?}");
        }
        let num: f64 = std::str::from_utf8(&bytes[start..i])
            .ok()
            .and_then(|t| t.parse().ok())
            .with_context(|| format!("bad duration {raw:?}"))?;
        let unit_start = i;
        while i < bytes.len() && bytes[i].is_ascii_alphabetic() {
            i += 1;
        }
        let unit = std::str::from_utf8(&bytes[unit_start..i]).unwrap_or("");
        if unit.is_empty() {
            bail!("time: missing unit in duration {raw:?}");
        }
        let mul = match unit {
            "ns" => 1.0,
            "us" | "µs" | "μs" => 1_000.0,
            "ms" => 1_000_000.0,
            "s" => 1_000_000_000.0,
            "m" => 60.0 * 1_000_000_000.0,
            "h" => 3600.0 * 1_000_000_000.0,
            other => bail!("unknown unit {other:?} in duration {raw:?}"),
        };
        total += Duration::from_nanos((num * mul) as u64);
    }
    Ok(total)
}

pub fn print_long_running_usage() {
    let bin = std::env::args()
        .next()
        .unwrap_or_else(|| "waf-sklookup-loader".into());
    eprint!(
        "Usage: {bin} [flags]                    # long-running toy / openresty\n\
         {pad} {bin} ctl ...                    # product control plane (Unix socket)\n\
         {pad} {bin} <add|remove|list|bulk> ... # root CLI escape hatch (pinned maps)\n\n\
         Rust userspace loader with selectable C/Rust BPF dataplanes.\n\n\
           -bpf string\n        c | rust (default \"c\"; env BPF_IMPL when omitted)\n\
           -mode string\n        toy | openresty | close-port | open-port | dump-ports (default \"toy\")\n\
           -listen string\n        toy mode: real server listen address (default \"127.0.0.1:18080\")\n\
           -target string\n        openresty mode: primary internal listen (default \"127.0.0.1:8080\")\n\
           -ports string\n        steered ports for the primary listen (default \"18081,18082,65500\")\n\
           -tls-target string\n        STOCK FALLBACK only: TLS listen (default \"127.0.0.1:8443\")\n\
           -tls-ports string\n        STOCK FALLBACK steered TLS ports (empty = product path)\n\
           -wait duration\n        openresty mode: max time to wait for target listen (default 60s)\n\
           -rescan-interval duration\n        OpenResty worker health rescan (default \"500ms\"; min 100ms; env RESCAN_INTERVAL)\n\
           -pin-dir string\n        bpffs directory for pinned maps (default \"/sys/fs/bpf/waf-sklookup\")\n\
           -ports-file string\n        desired open_ports file (default \"ports.conf\")\n\
           -policy-file string\n        binding/deny/quota policy (default policy.conf next to ports file)\n\
           -tenant string, -site string\n        mandatory binding when seeding or opening ports (see docs/binding.md)\n\
           -cert string, -policy string\n        optional stored binding identifiers\n\
           -ctl-sock string\n        authenticated Unix control socket (default \"/run/waf-sklookup/ctl.sock\"; empty disables)\n\
           -ctl-group uint\n        optional numeric group owner for the control socket\n\
           -no-ctl\n        disable the Unix control socket\n\
           -metrics-listen string\n        read-only Prometheus exporter address (default \"127.0.0.1:9101\"; env METRICS_LISTEN)\n\
           -no-metrics\n        disable the Prometheus exporter\n\n",
        pad = "       "
    );
    eprint!("{}", crate::ctl::CTL_USAGE);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctl_command_set() {
        for c in [
            "add",
            "remove",
            "list",
            "bulk",
            "fill",
            "load-ports",
            "close-ports",
            "open",
            "close",
            "dump",
            "help",
            "reconcile",
            "apply",
            "apply-central",
            "freeze",
            "unfreeze",
            "close-all",
            "rescan-listen",
            "import-listens",
            "import-listen",
            "migrate",
            "check-overlap",
            "retire-conf-listen",
            "status",
            "metrics",
        ] {
            assert!(is_ctl_command(c), "{c} should be a ctl command");
        }
        assert!(!is_ctl_command("-mode"));
        assert!(!is_ctl_command("toy"));
        assert!(!is_ctl_command("openresty"));
    }

    #[test]
    fn rescan_is_ops_command_not_attach_mode() {
        assert!(is_ctl_command("rescan-listen"));
        assert!(RunMode::parse("rescan-listen").is_err());
    }

    #[test]
    fn parse_duration_demo_values() {
        assert_eq!(parse_duration("60s").unwrap(), Duration::from_secs(60));
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_duration("1m").unwrap(), Duration::from_secs(60));
        assert!(parse_duration("60").is_err());
    }

    #[test]
    fn go_flags_single_dash() {
        let argv = vec![
            "-mode".into(),
            "openresty".into(),
            "-ports".into(),
            "18081".into(),
        ];
        let f = parse_go_flags(&argv, &[], &["mode", "ports"]).unwrap();
        assert_eq!(f.get("mode"), Some("openresty"));
        assert!(f.flag_set("ports"));
    }

    #[test]
    fn positional_ports_can_precede_binding_flags() {
        let argv = vec![
            "18183".into(),
            "-tenant".into(),
            "acme".into(),
            "-site".into(),
            "www".into(),
            "18184-18185".into(),
        ];
        let f = parse_go_flags(&argv, &[], &["tenant", "site"]).unwrap();
        assert_eq!(f.args, vec!["18183", "18184-18185"]);
        assert_eq!(f.get("tenant"), Some("acme"));
        assert_eq!(f.get("site"), Some("www"));
    }

    #[test]
    fn double_dash_still_ends_flag_parsing() {
        let argv = vec![
            "-tenant".into(),
            "acme".into(),
            "--".into(),
            "-literal".into(),
        ];
        let f = parse_go_flags(&argv, &[], &["tenant"]).unwrap();
        assert_eq!(f.get("tenant"), Some("acme"));
        assert_eq!(f.args, vec!["-literal"]);
    }

    #[test]
    fn rescan_interval_defaults_to_500ms_and_is_bounded() {
        std::env::remove_var("RESCAN_INTERVAL");
        assert_eq!(
            parse_long_running(&[]).unwrap().rescan_interval,
            Duration::from_millis(500)
        );
        let args = vec!["-rescan-interval".into(), "200ms".into()];
        assert_eq!(
            parse_long_running(&args).unwrap().rescan_interval,
            Duration::from_millis(200)
        );
        let too_fast = vec!["-rescan-interval".into(), "99ms".into()];
        assert!(parse_long_running(&too_fast).is_err());
    }

    #[test]
    fn metrics_listen_defaults_to_loopback_and_can_be_disabled() {
        std::env::remove_var("METRICS_LISTEN");
        assert_eq!(
            parse_long_running(&[]).unwrap().metrics_listen.as_deref(),
            Some("127.0.0.1:9101"),
            "exporter must default to loopback, never 0.0.0.0"
        );
        assert!(parse_long_running(&["-no-metrics".into()])
            .unwrap()
            .metrics_listen
            .is_none());
        let args = vec!["-metrics-listen".into(), "127.0.0.1:19999".into()];
        assert_eq!(
            parse_long_running(&args).unwrap().metrics_listen.as_deref(),
            Some("127.0.0.1:19999")
        );
    }

    #[test]
    fn bpf_impl_default_flag_and_env() {
        std::env::remove_var("BPF_IMPL");
        assert_eq!(parse_long_running(&[]).unwrap().bpf_impl, BpfImpl::C);
        let args = vec!["--bpf=rust".into()];
        assert_eq!(parse_long_running(&args).unwrap().bpf_impl, BpfImpl::Rust);
        std::env::set_var("BPF_IMPL", "rust");
        assert_eq!(parse_long_running(&[]).unwrap().bpf_impl, BpfImpl::Rust);
        let args = vec!["-bpf".into(), "c".into()];
        assert_eq!(parse_long_running(&args).unwrap().bpf_impl, BpfImpl::C);
        std::env::remove_var("BPF_IMPL");
        assert!(parse_long_running(&["-bpf=wat".into()]).is_err());
    }
}
