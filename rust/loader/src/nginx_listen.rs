use std::collections::BTreeSet;

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

#[cfg(test)]
mod tests {
    use super::*;

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
    }
}
