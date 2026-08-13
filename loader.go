package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-strip -tags linux -cflags "-I/usr/include/x86_64-linux-gnu -I./bpf/headers" dispatch dispatch.bpf.c

type runMode string

const (
	modeToy       runMode = "toy"
	modeOpenResty runMode = "openresty"
	modeClosePort runMode = "close-port"
	modeOpenPort  runMode = "open-port"
	modeDumpPorts runMode = "dump-ports"
)

const defaultPinDir = "/sys/fs/bpf/waf-sklookup"

// Sockmap slots. Product path uses only slot 0 (one internal listen).
// Slot 1 is the stock OpenResty 1.19.3.2 TLS fallback listen, not the
// Tengine https_allow_http production model.
const (
	redirPrimary uint32 = 0
	redirTLS     uint32 = 1
)

func main() {
	if len(os.Args) > 1 && isCtlCommand(os.Args[1]) {
		if err := runCtl(os.Args[1:]); err != nil {
			log.Fatal(err)
		}
		return
	}

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags]                    # long-running toy / openresty\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "       %s <add|remove|list|bulk> ... # M2 control plane (pinned maps)\n\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprint(os.Stderr, "\n"+ctlUsage)
	}

	modeFlag := flag.String("mode", string(modeToy), "toy | openresty | close-port | open-port | dump-ports")
	listen := flag.String("listen", "127.0.0.1:18080", "toy mode: real server listen address")
	target := flag.String("target", "127.0.0.1:8080", "openresty mode: primary internal listen registered into sockmap slot 0")
	extra := flag.String("ports", "18081,18082,65500", "steered ports for the primary listen (comma-separated); close-port/open-port also use this list")
	tlsTarget := flag.String("tls-target", "127.0.0.1:8443", "STOCK FALLBACK only: second internal TLS listen (sockmap slot 1). Unused with Tengine https_allow_http.")
	tlsExtra := flag.String("tls-ports", "", "STOCK FALLBACK only: steered ports mapped to -tls-target. Empty = product path (all ports → -target).")
	wait := flag.Duration("wait", 60*time.Second, "openresty mode: max time to wait for target listen socket(s)")
	pinDir := flag.String("pin-dir", defaultPinDir, "bpffs directory for pinned maps (needed for close-port / open-port / bpftool)")
	flag.Parse()

	portsFlagSet := false
	tlsPortsFlagSet := false
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "ports":
			portsFlagSet = true
		case "tls-ports":
			tlsPortsFlagSet = true
		default:
			// Other flags do not affect map-edit port selection.
		}
	})

	mode := runMode(strings.ToLower(strings.TrimSpace(*modeFlag)))
	switch mode {
	case modeToy, modeOpenResty, modeClosePort, modeOpenPort, modeDumpPorts:
	default:
		log.Fatalf("unknown -mode %q (want toy, openresty, close-port, open-port, dump-ports)", *modeFlag)
	}

	if mode == modeClosePort || mode == modeOpenPort || mode == modeDumpPorts {
		httpPorts, tlsPorts, err := mapEditPortLists(portsFlagSet, *extra, tlsPortsFlagSet, *tlsExtra)
		if err != nil {
			log.Fatal(err)
		}
		switch mode {
		case modeClosePort:
			if len(httpPorts)+len(tlsPorts) == 0 {
				log.Fatal("close-port needs -ports and/or -tls-ports")
			}
			if err := closePinnedPorts(*pinDir, append(httpPorts, tlsPorts...)); err != nil {
				log.Fatal(err)
			}
			return
		case modeOpenPort:
			if len(httpPorts)+len(tlsPorts) == 0 {
				log.Fatal("open-port needs -ports and/or -tls-ports")
			}
			if err := openPinnedPorts(*pinDir, httpPorts, tlsPorts); err != nil {
				log.Fatal(err)
			}
			return
		case modeDumpPorts:
			if err := dumpPinnedPorts(*pinDir); err != nil {
				log.Fatal(err)
			}
			return
		default:
			var _never runMode = mode
			log.Fatalf("unhandled map-only mode %q", _never)
		}
	}

	objs := dispatchObjects{}
	if err := loadDispatchObjects(&objs, nil); err != nil {
		log.Fatalf("load BPF: %v\n(hint: need root/CAP_BPF and kernel sk_lookup)", err)
	}
	defer objs.Close()

	netns, err := os.Open("/proc/self/ns/net")
	if err != nil {
		log.Fatalf("open netns: %v", err)
	}
	defer netns.Close()

	l, err := link.AttachNetNs(int(netns.Fd()), objs.Dispatch)
	if err != nil {
		log.Fatalf("attach sk_lookup: %v", err)
	}
	defer l.Close()
	log.Printf("sk_lookup attached to current netns")

	steeredPorts, err := parsePortListAllowEmpty(*extra)
	if err != nil {
		log.Fatalf("bad -ports: %v", err)
	}
	tlsPorts, err := parsePortListAllowEmpty(*tlsExtra)
	if err != nil {
		log.Fatalf("bad -tls-ports: %v", err)
	}
	if overlap := portSetOverlap(steeredPorts, tlsPorts); len(overlap) > 0 {
		log.Fatalf("port listed in both -ports and -tls-ports: %v", overlap)
	}

	if err := pinMaps(*pinDir, &objs); err != nil {
		log.Printf("warning: pin maps at %s: %v (close-port / bpftool map delete will not work)", *pinDir, err)
	} else {
		log.Printf("pinned maps under %s (open_ports, redir_socket)", *pinDir)
		defer unpinMaps(*pinDir)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch mode {
	case modeToy:
		if len(steeredPorts) == 0 {
			log.Fatal("toy mode needs -ports")
		}
		if len(tlsPorts) > 0 {
			log.Fatal("toy mode does not use -tls-ports (HTTP only)")
		}
		if err := runToyMode(ctx, objs, *listen, steeredPorts); err != nil {
			log.Fatal(err)
		}
	case modeOpenResty:
		if len(steeredPorts) == 0 && len(tlsPorts) == 0 {
			log.Fatal("openresty mode needs -ports and/or -tls-ports")
		}
		if err := runOpenRestyMode(ctx, objs, *target, steeredPorts, *tlsTarget, tlsPorts, *wait); err != nil {
			log.Fatal(err)
		}
	default:
		var _never runMode = mode
		log.Fatalf("unhandled mode %q", _never)
	}
}

func runToyMode(ctx context.Context, objs dispatchObjects, listenAddr string, steeredPorts []uint16) error {
	ln, file, err := listenTCP(listenAddr)
	if err != nil {
		return err
	}
	defer ln.Close()
	defer file.Close()

	if err := registerListenFD(objs, file, redirPrimary); err != nil {
		return err
	}
	if err := openSteeredPorts(objs, steeredPorts, uint8(redirPrimary)); err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		local := r.Context().Value(http.LocalAddrContextKey)
		fmt.Fprintf(w, "sk_lookup demo OK\n")
		fmt.Fprintf(w, "server_listen=%s\n", listenAddr)
		fmt.Fprintf(w, "http_local_addr=%v\n", local)
		fmt.Fprintf(w, "remote=%s\n", r.RemoteAddr)
		fmt.Fprintf(w, "host=%s\n", r.Host)
		fmt.Fprintf(w, "path=%s\n", r.URL.Path)
	})

	srv := &http.Server{Handler: mux}
	go func() {
		log.Printf("HTTP server serving on %s (and steered ports)", listenAddr)
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("serve: %v", err)
		}
	}()

	printToyInstructions(listenAddr, steeredPorts)
	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

func runOpenRestyMode(ctx context.Context, objs dispatchObjects, targetAddr string, steeredPorts []uint16, tlsTargetAddr string, tlsPorts []uint16, wait time.Duration) error {
	log.Printf("openresty mode: product path is one internal listen (%s); sk_lookup does not classify HTTP vs TLS", targetAddr)
	if len(tlsPorts) > 0 {
		log.Printf("STOCK FALLBACK: also registering TLS listen %s for -tls-ports (stock OpenResty 1.19.3.2 has no https_allow_http)", tlsTargetAddr)
	}

	httpFile, err := waitForListenSocket(ctx, targetAddr, wait)
	if err != nil {
		return err
	}
	defer httpFile.Close()
	if err := registerListenFD(objs, httpFile, redirPrimary); err != nil {
		return err
	}
	if err := openSteeredPorts(objs, steeredPorts, uint8(redirPrimary)); err != nil {
		return err
	}

	if len(tlsPorts) > 0 {
		tlsFile, err := waitForListenSocket(ctx, tlsTargetAddr, wait)
		if err != nil {
			return fmt.Errorf("stock TLS fallback listen: %w", err)
		}
		defer tlsFile.Close()
		if err := registerListenFD(objs, tlsFile, redirTLS); err != nil {
			return err
		}
		if err := openSteeredPorts(objs, tlsPorts, uint8(redirTLS)); err != nil {
			return err
		}
	}

	printOpenRestyInstructions(targetAddr, steeredPorts, tlsTargetAddr, tlsPorts)
	<-ctx.Done()
	log.Printf("shutting down loader (OpenResty keeps running)")
	return nil
}

func waitForListenSocket(ctx context.Context, targetAddr string, wait time.Duration) (*os.File, error) {
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return nil, fmt.Errorf("bad listen address %q: %w", targetAddr, err)
	}
	port64, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("bad listen port %q: %w", portStr, err)
	}
	targetPort := uint16(port64)
	if host == "" {
		host = "0.0.0.0"
	}

	log.Printf("waiting for listen socket on %s (timeout %s)", targetAddr, wait)
	deadline := time.Now().Add(wait)
	var lastErr error
	nextLog := time.Now()
	for {
		file, err := findListenSocketFile(host, targetPort)
		if err == nil {
			return file, nil
		}
		lastErr = err
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("target listen %s not found: %w", targetAddr, lastErr)
		}
		if !nextLog.After(time.Now()) {
			log.Printf("waiting for %s: %v", targetAddr, err)
			nextLog = time.Now().Add(2 * time.Second)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func listenTCP(listenAddr string) (net.Listener, *os.File, error) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("listen %s: %w", listenAddr, err)
	}
	tcpLn, ok := ln.(*net.TCPListener)
	if !ok {
		ln.Close()
		return nil, nil, errors.New("not a TCP listener")
	}
	file, err := tcpLn.File()
	if err != nil {
		ln.Close()
		return nil, nil, fmt.Errorf("listener File(): %w", err)
	}
	return ln, file, nil
}

func registerListenFD(objs dispatchObjects, file *os.File, slot uint32) error {
	if slot > redirTLS {
		return fmt.Errorf("sockmap slot %d out of range", slot)
	}
	if err := objs.RedirSocket.Put(slot, uint64(file.Fd())); err != nil {
		return fmt.Errorf("sockmap put slot %d: %w", slot, err)
	}
	log.Printf("registered listening socket fd=%d in redir_socket[%d]", file.Fd(), slot)
	return nil
}

func openSteeredPorts(objs dispatchObjects, ports []uint16, slot uint8) error {
	for _, port := range ports {
		if err := objs.OpenPorts.Put(port, slot); err != nil {
			return fmt.Errorf("open_ports put %d: %w", port, err)
		}
		log.Printf("opened steered port %d → redir_socket[%d] (no userspace bind on that port)", port, slot)
	}
	return nil
}

func parsePortList(raw string) ([]uint16, error) {
	ports, err := parsePortListAllowEmpty(raw)
	if err != nil {
		return nil, err
	}
	if len(ports) == 0 {
		return nil, errors.New("no ports provided")
	}
	return ports, nil
}

func parsePortListAllowEmpty(raw string) ([]uint16, error) {
	var ports []uint16
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		port64, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("bad port %q: %w", p, err)
		}
		ports = append(ports, uint16(port64))
	}
	return ports, nil
}

func portSetOverlap(a, b []uint16) []uint16 {
	if len(a) == 0 || len(b) == 0 {
		return nil
	}
	seen := make(map[uint16]struct{}, len(a))
	for _, p := range a {
		seen[p] = struct{}{}
	}
	var out []uint16
	dup := make(map[uint16]struct{})
	for _, p := range b {
		if _, ok := seen[p]; !ok {
			continue
		}
		if _, already := dup[p]; already {
			continue
		}
		dup[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

func mapEditPortLists(portsFlagSet bool, portsRaw string, tlsFlagSet bool, tlsRaw string) (httpPorts, tlsPorts []uint16, err error) {
	if portsFlagSet {
		httpPorts, err = parsePortListAllowEmpty(portsRaw)
		if err != nil {
			return nil, nil, fmt.Errorf("bad -ports: %w", err)
		}
	}
	if tlsFlagSet {
		tlsPorts, err = parsePortListAllowEmpty(tlsRaw)
		if err != nil {
			return nil, nil, fmt.Errorf("bad -tls-ports: %w", err)
		}
	}
	return httpPorts, tlsPorts, nil
}

func pinMaps(dir string, objs *dispatchObjects) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	for _, name := range []string{"open_ports", "redir_socket"} {
		_ = os.Remove(filepath.Join(dir, name))
	}
	if err := objs.OpenPorts.Pin(filepath.Join(dir, "open_ports")); err != nil {
		return fmt.Errorf("pin open_ports: %w", err)
	}
	if err := objs.RedirSocket.Pin(filepath.Join(dir, "redir_socket")); err != nil {
		_ = objs.OpenPorts.Unpin()
		return fmt.Errorf("pin redir_socket: %w", err)
	}
	return nil
}

func unpinMaps(dir string) {
	_ = os.Remove(filepath.Join(dir, "open_ports"))
	_ = os.Remove(filepath.Join(dir, "redir_socket"))
	_ = os.Remove(dir)
}

func closePinnedPorts(pinDir string, ports []uint16) error {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, "open_ports"), nil)
	if err != nil {
		return fmt.Errorf("load pinned open_ports: %w (is the loader still running?)", err)
	}
	defer m.Close()
	for _, port := range ports {
		if err := m.Delete(port); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				log.Printf("steered port %d already closed", port)
				continue
			}
			return fmt.Errorf("delete port %d: %w", port, err)
		}
		log.Printf("closed steered port %d (removed from open_ports)", port)
	}
	return nil
}

func openPinnedPorts(pinDir string, httpPorts, tlsPorts []uint16) error {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, "open_ports"), nil)
	if err != nil {
		return fmt.Errorf("load pinned open_ports: %w (is the loader still running?)", err)
	}
	defer m.Close()
	if overlap := portSetOverlap(httpPorts, tlsPorts); len(overlap) > 0 {
		return fmt.Errorf("port listed in both -ports and -tls-ports: %v", overlap)
	}
	for _, port := range httpPorts {
		slot := uint8(redirPrimary)
		if err := m.Put(port, slot); err != nil {
			return fmt.Errorf("open port %d: %w", port, err)
		}
		log.Printf("opened steered port %d → redir_socket[%d]", port, slot)
	}
	for _, port := range tlsPorts {
		slot := uint8(redirTLS)
		if err := m.Put(port, slot); err != nil {
			return fmt.Errorf("open tls port %d: %w", port, err)
		}
		log.Printf("opened steered port %d → redir_socket[%d] (stock TLS fallback)", port, slot)
	}
	return nil
}

func dumpPinnedPorts(pinDir string) error {
	return listPinnedPorts(pinDir, os.Stdout, false)
}

func listPinnedPorts(pinDir string, w io.Writer, countOnly bool) error {
	m, err := loadPinnedOpenPorts(pinDir)
	if err != nil {
		return err
	}
	defer m.Close()
	var key uint16
	var val uint8
	n := 0
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		n++
		if countOnly {
			continue
		}
		label := "primary"
		if val == uint8(redirTLS) {
			label = "tls-fallback"
		}
		fmt.Fprintf(w, "%d\tredir=%d\t%s\n", key, val, label)
	}
	if err := iter.Err(); err != nil {
		return err
	}
	if countOnly {
		fmt.Fprintf(w, "count=%d\n", n)
	}
	return nil
}

func printToyInstructions(listenAddr string, steeredPorts []uint16) {
	host, realPort, _ := net.SplitHostPort(listenAddr)
	if host == "" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	fmt.Println("======== TOY DEMO READY ========")
	fmt.Printf("Real bind:   curl -sS http://%s:%s/\n", host, realPort)
	for _, port := range steeredPorts {
		fmt.Printf("Steered:     curl -sS http://%s:%d/\n", host, port)
	}
	fmt.Println("Without BPF those steered ports would fail to connect.")
	fmt.Println("Ctrl+C to stop.")
	fmt.Println("================================")
}

func printOpenRestyInstructions(targetAddr string, steeredPorts []uint16, tlsTargetAddr string, tlsPorts []uint16) {
	host, _, _ := net.SplitHostPort(targetAddr)
	if host == "" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	fmt.Println("======== OPENRESTY P1 READY ========")
	fmt.Println("Product: sk_lookup steers external ports to a fixed internal listen.")
	fmt.Println("Tengine https_allow_http: that one listen accepts HTTP and TLS.")
	fmt.Println("Stock 1.19.3.2: no https_allow_http; -tls-ports is a labeled fallback.")
	fmt.Printf("Internal HTTP: curl -sS http://%s/\n", targetAddr)
	for _, port := range steeredPorts {
		fmt.Printf("Steered HTTP:  curl -sS http://%s:%d/\n", host, port)
	}
	if len(tlsPorts) > 0 {
		fmt.Printf("Internal TLS (stock fallback): curl -sk https://%s/\n", tlsTargetAddr)
		for _, port := range tlsPorts {
			fmt.Printf("Steered TLS (stock fallback):  curl -sk https://%s:%d/\n", host, port)
		}
	}
	fmt.Println("Default responses omit X-Waf-External-Port; access_log still has $waf_external_port.")
	fmt.Println("Expose header: WAF_EXPOSE_EXTERNAL_PORT=1 (restart OpenResty).")
	fmt.Println("M2 ctl: sudo ./waf-sklookup-demo add|remove|list|bulk  (no OpenResty reload)")
	fmt.Println("Close:  sudo ./waf-sklookup-demo remove 18081")
	fmt.Println("Reopen: sudo ./waf-sklookup-demo add 18081")
	fmt.Println("Legacy: sudo ./waf-sklookup-demo -mode close-port -ports 18081")
	fmt.Println("Ctrl+C to stop the loader (OpenResty keeps running).")
	fmt.Println("====================================")
}
