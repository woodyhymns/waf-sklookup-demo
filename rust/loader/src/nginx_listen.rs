use std::collections::{BTreeSet, HashMap};

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
        if !rest.starts_with(char::is_whitespace) { continue; }
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
}
