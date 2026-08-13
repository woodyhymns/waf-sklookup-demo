package main

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// parsePortNumber accepts 1..65535. Port 0 is rejected (not a usable TCP listen).
func parsePortNumber(raw string) (uint16, error) {
	s := strings.TrimSpace(raw)
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("bad port %q: %w", raw, err)
	}
	if n == 0 {
		return 0, fmt.Errorf("port 0 is not allowed")
	}
	return uint16(n), nil
}

// parsePortRange expands "START-END" inclusive. A 60K range is O(n) allocation, not a map walk.
func parsePortRange(raw string) ([]uint16, error) {
	s := strings.TrimSpace(raw)
	startStr, endStr, ok := strings.Cut(s, "-")
	if !ok || startStr == "" || endStr == "" || strings.Contains(endStr, "-") {
		return nil, fmt.Errorf("bad port range %q (want START-END)", raw)
	}
	start, err := parsePortNumber(startStr)
	if err != nil {
		return nil, fmt.Errorf("bad port range %q: %w", raw, err)
	}
	end, err := parsePortNumber(endStr)
	if err != nil {
		return nil, fmt.Errorf("bad port range %q: %w", raw, err)
	}
	if end < start {
		return nil, fmt.Errorf("port range %q has END < START", raw)
	}
	n := int(end) - int(start) + 1
	out := make([]uint16, n)
	for i := 0; i < n; i++ {
		out[i] = start + uint16(i)
	}
	return out, nil
}

// parsePortToken accepts a single port ("18081") or a range ("20000-20010").
func parsePortToken(raw string) ([]uint16, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, nil
	}
	if strings.Contains(s, "-") {
		return parsePortRange(s)
	}
	p, err := parsePortNumber(s)
	if err != nil {
		return nil, err
	}
	return []uint16{p}, nil
}

// parsePortListFlexible splits on commas; each token may be a port or START-END range.
func parsePortListFlexible(raw string) ([]uint16, error) {
	var out []uint16
	for _, tok := range strings.Split(raw, ",") {
		ports, err := parsePortToken(tok)
		if err != nil {
			return nil, err
		}
		out = append(out, ports...)
	}
	return out, nil
}

// loadPortsFromReader reads ports from a file or stdin.
// Lines may be comments (#), blank, comma-separated ports, or START-END ranges.
func loadPortsFromReader(r io.Reader) ([]uint16, error) {
	var out []uint16
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
			if line == "" {
				continue
			}
		}
		ports, err := parsePortListFlexible(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		out = append(out, ports...)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func uniquePorts(ports []uint16) []uint16 {
	if len(ports) == 0 {
		return ports
	}
	seen := make(map[uint16]struct{}, len(ports))
	out := make([]uint16, 0, len(ports))
	for _, p := range ports {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

func parseSkipSet(raw string) (map[uint16]struct{}, error) {
	ports, err := parsePortListAllowEmpty(raw)
	if err != nil {
		return nil, fmt.Errorf("bad -skip: %w", err)
	}
	skip := make(map[uint16]struct{}, len(ports))
	for _, p := range ports {
		skip[p] = struct{}{}
	}
	return skip, nil
}

// generateFillPorts returns `count` ports starting at `start`, skipping denylisted
// ports (default: OpenResty internal listens). Extends past start+count-1 when skips hit.
func generateFillPorts(start uint16, count int, skip map[uint16]struct{}) ([]uint16, error) {
	if count <= 0 {
		return nil, fmt.Errorf("fill -count must be > 0")
	}
	if count > openPortsMaxEntries {
		return nil, fmt.Errorf("fill -count %d exceeds open_ports max_entries %d", count, openPortsMaxEntries)
	}
	if start == 0 {
		return nil, fmt.Errorf("fill -start must be > 0")
	}
	out := make([]uint16, 0, count)
	p := start
	for {
		if _, hit := skip[p]; !hit {
			out = append(out, p)
			if len(out) == count {
				return out, nil
			}
		}
		if p == 65535 {
			break
		}
		p++
	}
	return nil, fmt.Errorf("not enough TCP ports: got %d want %d (start %d)", len(out), count, start)
}
