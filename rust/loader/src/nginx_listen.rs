use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::desired::{DesiredPorts, PortBinding};
use crate::policy::Policy;

pub fn inner_real_ports() -> BTreeSet<u16> {
    [80, 443, 8080, 8443].into_iter().collect()
}

pub fn parse_listen_ports(text: &str) -> Vec<u16> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for original in text.lines() {
        let line = original.split('#').next().unwrap_or("").trim();
        let Some(rest) = line.strip_prefix("listen") else { continue };
        if !rest.starts_with(char::is_whitespace) { continue };
        let address = rest.trim_start().split_whitespace().next().unwrap_or("").trim_end_matches(';');
        let raw = if address.bytes().all(|b| b.is_ascii_digit()) {
            address
        } else if let Some((_, port)) = address.rsplit_once(':') {
            port.trim_end_matches(';')
        } else { continue };
        if let Ok(port) = raw.parse::<u16>() {
            if port != 0 && seen.insert(port) { out.push(port); }
        }
    }
    out
}

pub fn importable_listen_ports(text: &str) -> Vec<u16> {
    let inner = inner_real_ports();
    parse_listen_ports(text).into_iter().filter(|p| !inner.contains(p)).collect()
}

pub fn real_listen_ports(text: &str) -> BTreeSet<u16> {
    let mut out = inner_real_ports();
    out.extend(parse_listen_ports(text));
    out
}

fn strip_comment(line: &str) -> &str {
    line.split('#').next().unwrap_or("").trim()
}

fn parse_include_specs(line: &str) -> Option<Vec<String>> {
    let line = strip_comment(line);
    let rest = line.strip_prefix("include")?;
    if !rest.starts_with(char::is_whitespace) {
        return None;
    }
    let spec = rest.trim().trim_end_matches(';').trim();
    if spec.is_empty() {
        return None;
    }
    Some(spec.split_whitespace().map(str::to_owned).collect())
}

fn resolve_include(base_dir: &Path, spec: &str) -> PathBuf {
    let path = Path::new(spec);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir.join(path)
    }
}

fn glob_matches(pattern: &str, name: &str) -> bool {
    let mut p = pattern.chars().peekable();
    let mut n = name.chars().peekable();
    loop {
        match (p.peek(), n.peek()) {
            (Some('*'), _) => {
                p.next();
                if p.peek().is_none() {
                    return true;
                }
                let suffix: String = p.collect();
                for (idx, _) in name.char_indices().rev() {
                    if glob_matches(&suffix, &name[idx..]) {
                        return true;
                    }
                }
                return false;
            }
            (Some('?'), Some(nc)) => {
                if *nc == '/' {
                    return false;
                }
                p.next();
                n.next();
            }
            (Some(pc), Some(nc)) if pc == nc => {
                p.next();
                n.next();
            }
            (None, None) => return true,
            _ => return false,
        }
    }
}

fn expand_glob(path: &Path) -> Result<Vec<PathBuf>> {
    let raw = path.to_string_lossy();
    if !raw.contains('*') && !raw.contains('?') {
        return Ok(vec![path.to_path_buf()]);
    }
    let parent = path.parent().context("include glob missing parent directory")?;
    let pattern = path
        .file_name()
        .and_then(|n| n.to_str())
        .context("include glob missing filename pattern")?;
    let mut matches = Vec::new();
    if parent.exists() {
        for entry in fs::read_dir(parent).with_context(|| format!("read include directory {}", parent.display()))? {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if glob_matches(pattern, &name_str) {
                matches.push(parent.join(name));
            }
        }
    }
    matches.sort();
    Ok(matches)
}

fn visit_key(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

pub fn read_expanded_files(root: &Path) -> Result<Vec<(PathBuf, String)>> {
    let mut visited = HashSet::new();
    let mut out = Vec::new();
    walk_includes(root, &mut visited, &mut out)?;
    Ok(out)
}

fn walk_includes(path: &Path, visited: &mut HashSet<PathBuf>, out: &mut Vec<(PathBuf, String)>) -> Result<()> {
    let key = visit_key(path);
    if !visited.insert(key) {
        return Ok(());
    }
    let text = fs::read_to_string(path).with_context(|| format!("read nginx config {}", path.display()))?;
    out.push((path.to_path_buf(), text.clone()));
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    for line in text.lines() {
        let Some(specs) = parse_include_specs(line) else { continue };
        for spec in specs {
            let resolved = resolve_include(base, &spec);
            for inc in expand_glob(&resolved)? {
                walk_includes(&inc, visited, out)?;
            }
        }
    }
    Ok(())
}

pub fn parse_listen_ports_from_conf(path: &Path) -> Result<Vec<u16>> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for (_, text) in read_expanded_files(path)? {
        for port in parse_listen_ports(&text) {
            if seen.insert(port) {
                out.push(port);
            }
        }
    }
    Ok(out)
}

pub fn importable_listen_ports_from_conf(path: &Path) -> Result<Vec<u16>> {
    let inner = inner_real_ports();
    Ok(parse_listen_ports_from_conf(path)?
        .into_iter()
        .filter(|p| !inner.contains(p))
        .collect())
}

pub fn real_listen_ports_from_conf(path: &Path) -> Result<BTreeSet<u16>> {
    let mut out = inner_real_ports();
    out.extend(parse_listen_ports_from_conf(path)?);
    Ok(out)
}

pub fn skip_reason(port: u16, policy: &Policy, extra_skip: &BTreeSet<u16>) -> Option<&'static str> {
    if port == 80 || port == 443 { return Some("reserved real bind"); }
    if extra_skip.contains(&port) { return Some("skipped real listen"); }
    if policy.deny.contains(&port) { return Some("denied by policy"); }
    if port <= 1023 && !policy.allow_privileged.contains(&port) { return Some("privileged"); }
    None
}

pub fn importable_ports(listens: &BTreeSet<u16>, policy: &Policy, extra_skip: &BTreeSet<u16>) -> (Vec<u16>, Vec<(u16, String)>) {
    let mut accepted = Vec::new();
    let mut skipped = Vec::new();
    for port in listens {
        if let Some(reason) = skip_reason(*port, policy, extra_skip) {
            skipped.push((*port, reason.to_string()));
        } else {
            accepted.push(*port);
        }
    }
    (accepted, skipped)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenKind { Virtual, Real, Conflict }

impl ListenKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Virtual => "virtual",
            Self::Real => "real",
            Self::Conflict => "conflict",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenRow {
    pub port: u16,
    pub kind: ListenKind,
    pub slot: Option<u8>,
    pub tenant: Option<String>,
    pub site: Option<String>,
}

pub fn classify(desired: &DesiredPorts, map: &HashMap<u16, u8>, real: &BTreeSet<u16>) -> Vec<ListenRow> {
    let ports: BTreeSet<u16> = desired.keys().copied().chain(map.keys().copied()).chain(real.iter().copied()).collect();
    let mut rows = Vec::new();
    for port in ports.iter().copied() {
        let in_virtual = desired.contains_key(&port) || map.contains_key(&port);
        let in_real = real.contains(&port);
        let kind = match (in_virtual, in_real) {
            (true, true) => ListenKind::Conflict,
            (true, false) => ListenKind::Virtual,
            (false, true) => ListenKind::Real,
            (false, false) => continue,
        };
        let binding: Option<&PortBinding> = desired.get(&port);
        rows.push(ListenRow {
            port,
            kind,
            slot: binding.map(|b| b.slot).or_else(|| map.get(&port).copied()),
            tenant: binding.map(|b| b.tenant.clone()),
            site: binding.map(|b| b.site.clone()),
        });
    }
    rows
}

pub fn conflicts(real_listens: &BTreeSet<u16>, candidates: impl IntoIterator<Item = u16>) -> Vec<u16> {
    let mut out: Vec<u16> = candidates.into_iter().filter(|p| real_listens.contains(p)).collect();
    out.sort_unstable();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pin::REDIR_PRIMARY;
    use std::path::PathBuf;

    fn issue30_fixture_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/issue-30-product-nginx/nginx.conf")
    }

    #[test]
    fn parses_supported_forms_comments_and_unique_order() {
        let text = r#"
            # listen 9999;
            listen 8080;
            listen 127.0.0.1:8080;
            listen *:18081 default_server reuseport;
            listen [::]:18082;
            listen 127.0.0.1:8443 ssl https_allow_http;
            worker_processes 1;
        "#;
        assert_eq!(parse_listen_ports(text), vec![8080, 18081, 18082, 8443]);
        assert_eq!(importable_listen_ports(text), vec![18081, 18082]);
    }

    #[test]
    fn import_never_includes_inner_or_web_ports() {
        assert_eq!(importable_listen_ports("listen 80;\nlisten 443;\nlisten 19001;"), vec![19001]);
        assert_eq!(inner_real_ports(), [80, 443, 8080, 8443].into_iter().collect());
        let policy = Policy::default();
        let listens = [80, 443, 22, 19001].into_iter().collect();
        let (accepted, skipped) = importable_ports(&listens, &policy, &BTreeSet::new());
        assert_eq!(accepted, vec![19001]);
        assert!(skipped.iter().any(|(p, r)| *p == 80 && r.contains("reserved")));
        assert!(skipped.iter().any(|(p, r)| *p == 443 && r.contains("reserved")));
        assert!(skipped.iter().any(|(p, r)| *p == 22 && r.contains("denied")));
    }

    #[test]
    fn classify_marks_virtual_real_and_conflict() {
        let mut desired = DesiredPorts::new();
        desired.insert(18081, PortBinding { slot: REDIR_PRIMARY as u8, tenant: "acme".into(), site: "www".into(), cert: None, policy: None });
        desired.insert(8080, PortBinding { slot: REDIR_PRIMARY as u8, tenant: "acme".into(), site: "www".into(), cert: None, policy: None });
        let real = [80, 8080].into_iter().collect();
        let rows = classify(&desired, &HashMap::new(), &real);
        let kind = |p| rows.iter().find(|r| r.port == p).unwrap().kind;
        assert_eq!(kind(18081), ListenKind::Virtual);
        assert_eq!(kind(80), ListenKind::Real);
        assert_eq!(kind(8080), ListenKind::Conflict);
    }

    #[test]
    fn conflict_helper_is_intersection() {
        let real = [80, 8080, 18081].into_iter().collect();
        assert_eq!(conflicts(&real, [18081, 19001, 80]), vec![80, 18081]);
    }

    #[test]
    fn include_expansion_follows_globs_and_skips_cycles() {
        let root = issue30_fixture_root();
        let listens = parse_listen_ports_from_conf(&root).unwrap();
        assert!(listens.contains(&80));
        assert!(listens.contains(&443));
        assert!(listens.contains(&8080));
        assert!(listens.contains(&8443));
        assert!(listens.contains(&19001));
        assert!(listens.contains(&19002));
        assert!(listens.contains(&18081));
        assert!(listens.contains(&18082));

        let importable = importable_listen_ports_from_conf(&root).unwrap();
        assert_eq!(importable, vec![19001, 19002, 18081, 18082]);

        let real = real_listen_ports_from_conf(&root).unwrap();
        assert!(real.contains(&80));
        assert!(real.contains(&443));
        assert!(!importable.iter().any(|p| real.contains(p) && [80, 443, 8080, 8443].contains(p)));
    }

    #[test]
    fn include_cycle_is_deduped() {
        let dir = std::env::temp_dir().join(format!("waf-include-cycle-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("a.conf"), "include b.conf;\nlisten 19011;\n").unwrap();
        fs::write(dir.join("b.conf"), "include a.conf;\nlisten 19012;\n").unwrap();
        fs::write(dir.join("nginx.conf"), "include a.conf;\n").unwrap();
        let listens = parse_listen_ports_from_conf(&dir.join("nginx.conf")).unwrap();
        assert_eq!(listens, vec![19011, 19012]);
        let _ = fs::remove_dir_all(&dir);
    }
}
