package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParsePortRange(t *testing.T) {
	ports, err := parsePortRange("20000-20002")
	if err != nil {
		t.Fatal(err)
	}
	want := []uint16{20000, 20001, 20002}
	if len(ports) != len(want) {
		t.Fatalf("len=%d want %d", len(ports), len(want))
	}
	for i := range want {
		if ports[i] != want[i] {
			t.Fatalf("ports[%d]=%d want %d", i, ports[i], want[i])
		}
	}
	if _, err := parsePortRange("10-1"); err == nil {
		t.Fatal("expected END < START error")
	}
	if _, err := parsePortRange("0-10"); err == nil {
		t.Fatal("expected port 0 rejected")
	}
	if _, err := parsePortRange("10000"); err == nil {
		t.Fatal("expected missing hyphen error")
	}
}

func TestParsePortRangeScale(t *testing.T) {
	ports, err := parsePortRange("10000-39999")
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 30000 {
		t.Fatalf("30K range len=%d want 30000", len(ports))
	}
	if ports[0] != 10000 || ports[29999] != 39999 {
		t.Fatalf("range bounds got %d..%d", ports[0], ports[29999])
	}
	ports, err = parsePortRange("5000-64999")
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 60000 {
		t.Fatalf("60K range len=%d want 60000", len(ports))
	}
	if ports[0] != 5000 || ports[59999] != 64999 {
		t.Fatalf("60K bounds got %d..%d", ports[0], ports[59999])
	}
}

func TestParsePortListFlexible(t *testing.T) {
	ports, err := parsePortListFlexible("18081,20000-20002, 18082")
	if err != nil {
		t.Fatal(err)
	}
	want := []uint16{18081, 20000, 20001, 20002, 18082}
	if len(ports) != len(want) {
		t.Fatalf("got %v want %v", ports, want)
	}
	for i := range want {
		if ports[i] != want[i] {
			t.Fatalf("got %v want %v", ports, want)
		}
	}
}

func TestLoadPortsFromReader(t *testing.T) {
	in := "# comment\n18081\n20000-20001,20002\n  \n18082 # trailing\n"
	ports, err := loadPortsFromReader(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []uint16{18081, 20000, 20001, 20002, 18082}
	if len(ports) != len(want) {
		t.Fatalf("got %v want %v", ports, want)
	}
	for i := range want {
		if ports[i] != want[i] {
			t.Fatalf("got %v want %v", ports, want)
		}
	}
}

func TestLoadPortsFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ports.txt")
	body := "10000-10002\n10001\n# dup ok\n"
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ports, err := loadPortsFromReader(f)
	if err != nil {
		t.Fatal(err)
	}
	got := uniquePorts(ports)
	if len(got) != 3 || got[0] != 10000 || got[2] != 10002 {
		t.Fatalf("got %v want [10000 10001 10002]", got)
	}
}

func TestUniquePorts(t *testing.T) {
	got := uniquePorts([]uint16{2, 1, 2, 1, 3})
	if len(got) != 3 || got[0] != 2 || got[1] != 1 || got[2] != 3 {
		t.Fatalf("got %v want first-seen order [2 1 3]", got)
	}
}

func TestGenerateFillPorts(t *testing.T) {
	skip := map[uint16]struct{}{8080: {}, 8443: {}}
	ports, err := generateFillPorts(8078, 5, skip)
	if err != nil {
		t.Fatal(err)
	}
	want := []uint16{8078, 8079, 8081, 8082, 8083}
	if len(ports) != len(want) {
		t.Fatalf("got %v want %v", ports, want)
	}
	for i := range want {
		if ports[i] != want[i] {
			t.Fatalf("got %v want %v", ports, want)
		}
	}
	ports, err = generateFillPorts(10000, 30000, skip)
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 30000 || ports[0] != 10000 || ports[29999] != 39999 {
		t.Fatalf("30K fill bounds %d..%d len=%d", ports[0], ports[len(ports)-1], len(ports))
	}
	ports, err = generateFillPorts(5000, 60000, skip)
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 60000 || ports[0] != 5000 {
		t.Fatalf("60K fill start=%d len=%d", ports[0], len(ports))
	}
	if ports[len(ports)-1] > 65535 {
		t.Fatalf("60K fill last port %d overflows", ports[len(ports)-1])
	}
	for _, p := range ports {
		if p == 8080 || p == 8443 {
			t.Fatalf("fill included skipped internal listen %d", p)
		}
	}
	if _, err := generateFillPorts(65530, 20, nil); err == nil {
		t.Fatal("expected not enough ports")
	}
	if _, err := generateFillPorts(10000, 60000, nil); err == nil {
		t.Fatal("expected 60K from 10000 to fail (uint16 overflow)")
	}
	if _, err := generateFillPorts(0, 10, nil); err == nil {
		t.Fatal("expected start 0 rejected")
	}
}

func TestCollectBulkPortsRangeAndExtra(t *testing.T) {
	ports, err := collectBulkPorts("10-12", "", false, []string{"14", "11"})
	if err != nil {
		t.Fatal(err)
	}
	want := []uint16{10, 11, 12, 14}
	if len(ports) != len(want) {
		t.Fatalf("got %v want %v", ports, want)
	}
	for i := range want {
		if ports[i] != want[i] {
			t.Fatalf("got %v want %v", ports, want)
		}
	}
	if _, err := collectBulkPorts("", "", false, nil); err == nil {
		t.Fatal("expected empty sources error")
	}
}

func TestOpenPortsMaxEntries(t *testing.T) {
	if openPortsMaxEntries < 65536 {
		t.Fatalf("open_ports max_entries=%d; M3 30K/60K needs >= 65536", openPortsMaxEntries)
	}
	if openPortsMaxEntries < 60000 {
		t.Fatalf("open_ports max_entries=%d cannot hold a 60K fill", openPortsMaxEntries)
	}
	spec, err := loadDispatch()
	if err != nil {
		t.Fatal(err)
	}
	m := spec.Maps["open_ports"]
	if m == nil {
		t.Fatal("generated spec missing open_ports")
	}
	if m.MaxEntries != openPortsMaxEntries {
		t.Fatalf("BPF open_ports MaxEntries=%d want %d (rebuild with go generate)", m.MaxEntries, openPortsMaxEntries)
	}
	if m.MaxEntries < 65536 {
		t.Fatalf("BPF open_ports MaxEntries=%d still too small for M3", m.MaxEntries)
	}
}

func TestIsCtlCommand(t *testing.T) {
	for _, c := range []string{"add", "remove", "list", "bulk", "open", "close", "dump", "help"} {
		if !isCtlCommand(c) {
			t.Fatalf("%q should be a ctl command", c)
		}
	}
	if isCtlCommand("-mode") || isCtlCommand("toy") || isCtlCommand("openresty") {
		t.Fatal("long-running modes must not be captured as ctl commands")
	}
}

func TestFormatBulkSummary(t *testing.T) {
	s := formatBulkSummary("added", 30000, 0, bulkResult{})
	if !strings.Contains(s, "added n=30000") || !strings.Contains(s, "primary") {
		t.Fatalf("unexpected summary %q", s)
	}
	var buf bytes.Buffer
	reportBulkProgress(&buf, "add", 4096, 30000, time.Now())
	if buf.Len() == 0 {
		t.Fatal("expected progress line for large total")
	}
}
