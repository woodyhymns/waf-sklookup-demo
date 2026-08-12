package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
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
	modeDumpPorts runMode = "dump-ports"
)

const defaultPinDir = "/sys/fs/bpf/waf-sklookup"

func main() {
	modeFlag := flag.String("mode", string(modeToy), "toy | openresty | close-port | dump-ports")
	listen := flag.String("listen", "127.0.0.1:18080", "toy mode: real server listen address")
	target := flag.String("target", "127.0.0.1:8080", "openresty mode: internal listen whose socket FD is registered into sockmap")
	extra := flag.String("ports", "18081,18082,65500", "steered ports (comma-separated); close-port deletes these from open_ports")
	wait := flag.Duration("wait", 60*time.Second, "openresty mode: max time to wait for target listen socket")
	pinDir := flag.String("pin-dir", defaultPinDir, "bpffs directory for pinned maps (needed for close-port / bpftool)")
	flag.Parse()

	mode := runMode(strings.ToLower(strings.TrimSpace(*modeFlag)))
	switch mode {
	case modeToy, modeOpenResty, modeClosePort, modeDumpPorts:
	default:
		log.Fatalf("unknown -mode %q (want toy, openresty, close-port, dump-ports)", *modeFlag)
	}

	if mode == modeClosePort || mode == modeDumpPorts {
		ports, err := parsePortList(*extra)
		if err != nil && mode == modeClosePort {
			log.Fatalf("bad -ports: %v", err)
		}
		if mode == modeClosePort {
			if err := closePinnedPorts(*pinDir, ports); err != nil {
				log.Fatal(err)
			}
			return
		}
		if err := dumpPinnedPorts(*pinDir); err != nil {
			log.Fatal(err)
		}
		return
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

	steeredPorts, err := parsePortList(*extra)
	if err != nil {
		log.Fatalf("bad -ports: %v", err)
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
		if err := runToyMode(ctx, objs, *listen, steeredPorts); err != nil {
			log.Fatal(err)
		}
	case modeOpenResty:
		if err := runOpenRestyMode(ctx, objs, *target, steeredPorts, *wait); err != nil {
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

	if err := registerListenFD(objs, file); err != nil {
		return err
	}
	if err := openSteeredPorts(objs, steeredPorts); err != nil {
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

func runOpenRestyMode(ctx context.Context, objs dispatchObjects, targetAddr string, steeredPorts []uint16, wait time.Duration) error {
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return fmt.Errorf("bad -target %q: %w", targetAddr, err)
	}
	port64, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return fmt.Errorf("bad -target port %q: %w", portStr, err)
	}
	targetPort := uint16(port64)
	if host == "" {
		host = "0.0.0.0"
	}

	log.Printf("openresty mode: waiting for listen socket on %s (timeout %s)", targetAddr, wait)
	deadline := time.Now().Add(wait)
	var file *os.File
	var lastErr error
	nextLog := time.Now()
	for {
		file, err = findListenSocketFile(host, targetPort)
		if err == nil {
			break
		}
		lastErr = err
		if time.Now().After(deadline) {
			return fmt.Errorf("target listen %s not found: %w", targetAddr, lastErr)
		}
		if !nextLog.After(time.Now()) {
			log.Printf("waiting for %s: %v", targetAddr, err)
			nextLog = time.Now().Add(2 * time.Second)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	defer file.Close()

	if err := registerListenFD(objs, file); err != nil {
		return err
	}
	if err := openSteeredPorts(objs, steeredPorts); err != nil {
		return err
	}

	printOpenRestyInstructions(targetAddr, steeredPorts)
	<-ctx.Done()
	log.Printf("shutting down loader (OpenResty keeps running)")
	return nil
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

func registerListenFD(objs dispatchObjects, file *os.File) error {
	var key uint32
	if err := objs.RedirSocket.Put(key, uint64(file.Fd())); err != nil {
		return fmt.Errorf("sockmap put: %w", err)
	}
	log.Printf("registered listening socket fd=%d in redir_socket sockmap", file.Fd())
	return nil
}

func openSteeredPorts(objs dispatchObjects, ports []uint16) error {
	for _, port := range ports {
		one := uint8(1)
		if err := objs.OpenPorts.Put(port, one); err != nil {
			return fmt.Errorf("open_ports put %d: %w", port, err)
		}
		log.Printf("opened steered port %d (no userspace bind on that port)", port)
	}
	return nil
}

func parsePortList(raw string) ([]uint16, error) {
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
	if len(ports) == 0 {
		return nil, errors.New("no ports provided")
	}
	return ports, nil
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
			return fmt.Errorf("delete port %d: %w", port, err)
		}
		log.Printf("closed steered port %d (removed from open_ports)", port)
	}
	return nil
}

func dumpPinnedPorts(pinDir string) error {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, "open_ports"), nil)
	if err != nil {
		return fmt.Errorf("load pinned open_ports: %w", err)
	}
	defer m.Close()
	var key uint16
	var val uint8
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		fmt.Printf("%d\n", key)
	}
	if err := iter.Err(); err != nil {
		return err
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

func printOpenRestyInstructions(targetAddr string, steeredPorts []uint16) {
	host, _, _ := net.SplitHostPort(targetAddr)
	if host == "" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	fmt.Println("======== OPENRESTY M1 READY ========")
	fmt.Printf("Internal:    curl -sS http://%s/\n", targetAddr)
	for _, port := range steeredPorts {
		fmt.Printf("Steered:     curl -sS http://%s:%d/\n", host, port)
	}
	fmt.Println("Only the internal listen should appear in ss/proc; steered ports have no bind().")
	fmt.Println("Check X-Waf-External-Port header and access log for $waf_external_port.")
	fmt.Println("Close a port: sudo ./waf-sklookup-demo -mode close-port -ports 18081")
	fmt.Println("Ctrl+C to stop the loader (OpenResty keeps running).")
	fmt.Println("====================================")
}
