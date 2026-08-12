package main

import (
	"net"
	"testing"
)

func TestParsePortList(t *testing.T) {
	ports, err := parsePortList("18081, 18082,65500")
	if err != nil {
		t.Fatal(err)
	}
	want := []uint16{18081, 18082, 65500}
	if len(ports) != len(want) {
		t.Fatalf("len=%d want %d", len(ports), len(want))
	}
	for i := range want {
		if ports[i] != want[i] {
			t.Fatalf("ports[%d]=%d want %d", i, ports[i], want[i])
		}
	}
	if _, err := parsePortList(""); err == nil {
		t.Fatal("expected error for empty list")
	}
	if _, err := parsePortList("notaport"); err == nil {
		t.Fatal("expected error for bad port")
	}
}

func TestParseListenInode(t *testing.T) {
	// 127.0.0.1:8080 LISTEN, inode 4242
	table := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4242 1 0000000000000000 100 0 0 10 0\n"
	inode, err := parseListenInode(table, net.IPv4(127, 0, 0, 1), 8080)
	if err != nil {
		t.Fatal(err)
	}
	if inode != 4242 {
		t.Fatalf("inode=%d want 4242", inode)
	}
	if _, err := parseListenInode(table, net.IPv4(127, 0, 0, 1), 18081); err == nil {
		t.Fatal("expected miss for unbound port")
	}
}

func TestIPToProcHex(t *testing.T) {
	got := ipToProcHex(net.IPv4(127, 0, 0, 1))
	if got != 0x0100007F {
		t.Fatalf("got 0x%08X want 0x0100007F", got)
	}
}
