//! Port / range / file / stdin / bulk-fill generation (parity with `portspec.go`).

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read};

use anyhow::{bail, Context, Result};

use crate::pin::OPEN_PORTS_MAX_ENTRIES;

/// Accepts 1..=65535. Port 0 is rejected (not a usable TCP listen).
pub fn parse_port_number(raw: &str) -> Result<u16> {
    let s = raw.trim();
    let n: u64 = s.parse().with_context(|| format!("bad port {raw:?}"))?;
    if n == 0 {
        bail!("port 0 is not allowed");
    }
    if n > u64::from(u16::MAX) {
        bail!("bad port {raw:?}");
    }
    Ok(n as u16)
}

/// Long-running `-ports` list: comma-separated, empty tokens skipped. Port 0 is allowed
/// here to match Go `parsePortListAllowEmpty` (`strconv.ParseUint(..., 16)`).
pub fn parse_port_list_allow_empty(raw: &str) -> Result<Vec<u16>> {
    let mut ports = Vec::new();
    for p in raw.split(',') {
        let p = p.trim();
        if p.is_empty() {
            continue;
        }
        let n: u64 = p.parse().with_context(|| format!("bad port {p:?}"))?;
        if n > u64::from(u16::MAX) {
            bail!("bad port {p:?}");
        }
        ports.push(n as u16);
    }
    Ok(ports)
}

#[allow(dead_code)]
pub fn parse_port_list(raw: &str) -> Result<Vec<u16>> {
    let ports = parse_port_list_allow_empty(raw)?;
    if ports.is_empty() {
        bail!("no ports provided");
    }
    Ok(ports)
}

/// Inclusive START-END. A 60K range is O(n) allocation, not a map walk.
pub fn parse_port_range(raw: &str) -> Result<Vec<u16>> {
    let s = raw.trim();
    let Some((start_str, end_str)) = s.split_once('-') else {
        bail!("bad port range {raw:?} (want START-END)");
    };
    if start_str.is_empty() || end_str.is_empty() || end_str.contains('-') {
        bail!("bad port range {raw:?} (want START-END)");
    }
    let start = parse_port_number(start_str).with_context(|| format!("bad port range {raw:?}"))?;
    let end = parse_port_number(end_str).with_context(|| format!("bad port range {raw:?}"))?;
    if end < start {
        bail!("port range {raw:?} has END < START");
    }
    let n = usize::from(end) - usize::from(start) + 1;
    let mut out = Vec::with_capacity(n);
    let mut p = start;
    loop {
        out.push(p);
        if p == end {
            break;
        }
        p += 1;
    }
    Ok(out)
}

pub fn parse_port_token(raw: &str) -> Result<Vec<u16>> {
    let s = raw.trim();
    if s.is_empty() {
        return Ok(Vec::new());
    }
    if s.contains('-') {
        return parse_port_range(s);
    }
    Ok(vec![parse_port_number(s)?])
}

/// Splits on commas; each token may be a port or START-END range.
pub fn parse_port_list_flexible(raw: &str) -> Result<Vec<u16>> {
    let mut out = Vec::new();
    for tok in raw.split(',') {
        out.extend(parse_port_token(tok)?);
    }
    Ok(out)
}

/// Lines may be comments (#), blank, comma-separated ports, or START-END ranges.
pub fn load_ports_from_reader(r: impl Read) -> Result<Vec<u16>> {
    let mut out = Vec::new();
    let reader = BufReader::new(r);
    for (i, line) in reader.lines().enumerate() {
        let line_no = i + 1;
        let mut line = line.with_context(|| format!("line {line_no}"))?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(idx) = line.find('#') {
            line = line[..idx].to_string();
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let ports = parse_port_list_flexible(line).with_context(|| format!("line {line_no}"))?;
        out.extend(ports);
    }
    Ok(out)
}

pub fn unique_ports(ports: Vec<u16>) -> Vec<u16> {
    let mut seen = HashSet::with_capacity(ports.len());
    let mut out = Vec::with_capacity(ports.len());
    for p in ports {
        if seen.insert(p) {
            out.push(p);
        }
    }
    out
}

pub fn parse_skip_set(raw: &str) -> Result<HashMap<u16, ()>> {
    let ports = parse_port_list_allow_empty(raw).with_context(|| "bad -skip")?;
    let mut skip = HashMap::with_capacity(ports.len());
    for p in ports {
        skip.insert(p, ());
    }
    Ok(skip)
}

/// `count` ports starting at `start`, skipping denylisted ports.
/// Extends past start+count-1 when skips hit. Must not wrap uint16.
pub fn generate_fill_ports(start: u16, count: usize, skip: &HashMap<u16, ()>) -> Result<Vec<u16>> {
    if count == 0 {
        bail!("fill -count must be > 0");
    }
    if count > OPEN_PORTS_MAX_ENTRIES as usize {
        bail!("fill -count {count} exceeds open_ports max_entries {OPEN_PORTS_MAX_ENTRIES}");
    }
    if start == 0 {
        bail!("fill -start must be > 0");
    }
    let mut out = Vec::with_capacity(count);
    let mut p = start;
    loop {
        if !skip.contains_key(&p) {
            out.push(p);
            if out.len() == count {
                return Ok(out);
            }
        }
        if p == u16::MAX {
            break;
        }
        p += 1;
    }
    bail!(
        "not enough TCP ports: got {} want {} (start {start})",
        out.len(),
        count
    )
}

pub fn port_set_overlap(a: &[u16], b: &[u16]) -> Vec<u16> {
    if a.is_empty() || b.is_empty() {
        return Vec::new();
    }
    let seen: HashSet<u16> = a.iter().copied().collect();
    let mut out = Vec::new();
    let mut dup = HashSet::new();
    for p in b {
        if seen.contains(p) && dup.insert(*p) {
            out.push(*p);
        }
    }
    out
}

pub fn collect_bulk_ports(
    range_spec: Option<&str>,
    file_path: Option<&str>,
    from_stdin: bool,
    extra: &[String],
) -> Result<Vec<u16>> {
    let mut out = Vec::new();
    if let Some(range_spec) = range_spec.filter(|s| !s.is_empty()) {
        out.extend(parse_port_range(range_spec)?);
    }
    if let Some(file_path) = file_path.filter(|s| !s.is_empty()) {
        let f = std::fs::File::open(file_path).with_context(|| format!("open {file_path}"))?;
        let ports = load_ports_from_reader(f).with_context(|| format!("read {file_path}"))?;
        out.extend(ports);
    }
    if from_stdin {
        let ports = load_ports_from_reader(std::io::stdin()).context("stdin")?;
        out.extend(ports);
    }
    for a in extra {
        out.extend(parse_port_list_flexible(a)?);
    }
    out = unique_ports(out);
    if out.is_empty() {
        bail!("bulk needs -range, -file, -stdin, and/or positional ports");
    }
    if out.len() > OPEN_PORTS_MAX_ENTRIES as usize {
        bail!(
            "bulk list has {} ports; open_ports max_entries is {OPEN_PORTS_MAX_ENTRIES}",
            out.len()
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn parse_port_range_ok() {
        let ports = parse_port_range("20000-20002").unwrap();
        assert_eq!(ports, vec![20000, 20001, 20002]);
        assert!(parse_port_range("10-1").is_err());
        assert!(parse_port_range("0-10").is_err());
        assert!(parse_port_range("10000").is_err());
    }

    #[test]
    fn parse_port_range_scale() {
        let ports = parse_port_range("10000-39999").unwrap();
        assert_eq!(ports.len(), 30000);
        assert_eq!(ports[0], 10000);
        assert_eq!(ports[29999], 39999);
        let ports = parse_port_range("5000-64999").unwrap();
        assert_eq!(ports.len(), 60000);
        assert_eq!(ports[0], 5000);
        assert_eq!(ports[59999], 64999);
    }

    #[test]
    fn parse_port_list_flexible_ok() {
        let ports = parse_port_list_flexible("18081,20000-20002, 18082").unwrap();
        assert_eq!(ports, vec![18081, 20000, 20001, 20002, 18082]);
    }

    #[test]
    fn load_ports_from_reader_ok() {
        let in_ = "# comment\n18081\n20000-20001,20002\n  \n18082 # trailing\n";
        let ports = load_ports_from_reader(Cursor::new(in_)).unwrap();
        assert_eq!(ports, vec![18081, 20000, 20001, 20002, 18082]);
    }

    #[test]
    fn unique_ports_first_seen() {
        let got = unique_ports(vec![2, 1, 2, 1, 3]);
        assert_eq!(got, vec![2, 1, 3]);
    }

    #[test]
    fn generate_fill_ports_skip_and_scale() {
        let skip = HashMap::from([(8080, ()), (8443, ())]);
        let ports = generate_fill_ports(8078, 5, &skip).unwrap();
        assert_eq!(ports, vec![8078, 8079, 8081, 8082, 8083]);
        let ports = generate_fill_ports(10000, 30000, &skip).unwrap();
        assert_eq!(ports.len(), 30000);
        assert_eq!(ports[0], 10000);
        assert_eq!(ports[29999], 39999);
        let ports = generate_fill_ports(5000, 60000, &skip).unwrap();
        assert_eq!(ports.len(), 60000);
        assert_eq!(ports[0], 5000);
        for p in &ports {
            assert_ne!(*p, 8080);
            assert_ne!(*p, 8443);
        }
        assert!(generate_fill_ports(65530, 20, &HashMap::new()).is_err());
        assert!(generate_fill_ports(10000, 60000, &HashMap::new()).is_err());
        assert!(generate_fill_ports(0, 10, &HashMap::new()).is_err());
    }

    #[test]
    fn collect_bulk_ports_range_and_extra() {
        let ports =
            collect_bulk_ports(Some("10-12"), None, false, &["14".into(), "11".into()]).unwrap();
        assert_eq!(ports, vec![10, 11, 12, 14]);
        assert!(collect_bulk_ports(None, None, false, &[]).is_err());
    }

    #[test]
    fn parse_port_list_and_empty() {
        let ports = parse_port_list("18081, 18082,65500").unwrap();
        assert_eq!(ports, vec![18081, 18082, 65500]);
        assert!(parse_port_list("").is_err());
        assert!(parse_port_list("notaport").is_err());
        assert!(parse_port_list_allow_empty("").unwrap().is_empty());
        assert!(parse_port_list_allow_empty("  ,  ").unwrap().is_empty());
        assert_eq!(parse_port_list_allow_empty("18443").unwrap(), vec![18443]);
    }

    #[test]
    fn port_set_overlap_ok() {
        assert_eq!(
            port_set_overlap(&[18081, 18082], &[18443, 18081]),
            vec![18081]
        );
        assert!(port_set_overlap(&[18081], &[]).is_empty());
        assert!(port_set_overlap(&[1, 2], &[3, 4]).is_empty());
    }
}
