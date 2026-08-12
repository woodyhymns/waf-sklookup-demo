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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux dispatch dispatch.bpf.c

func main() {
	listen := flag.String("listen", "127.0.0.1:18080", "real server listen address")
	extra := flag.String("ports", "18081,18082,65500", "extra ports steered via sk_lookup (comma-separated)")
	flag.Parse()

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

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("listen %s: %v", *listen, err)
	}
	defer ln.Close()

	tcpLn, ok := ln.(*net.TCPListener)
	if !ok {
		log.Fatalf("not a TCP listener")
	}
	file, err := tcpLn.File()
	if err != nil {
		log.Fatalf("listener File(): %v", err)
	}
	defer file.Close()

	var key uint32
	if err := objs.RedirSocket.Put(key, uint64(file.Fd())); err != nil {
		log.Fatalf("sockmap put: %v", err)
	}
	log.Printf("registered listening socket fd=%d for %s", file.Fd(), *listen)

	for _, p := range strings.Split(*extra, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		port64, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			log.Fatalf("bad port %q: %v", p, err)
		}
		port := uint16(port64)
		one := uint8(1)
		if err := objs.OpenPorts.Put(port, one); err != nil {
			log.Fatalf("open_ports put %d: %v", port, err)
		}
		log.Printf("opened steered port %d (no userspace bind on that port)", port)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		local := r.Context().Value(http.LocalAddrContextKey)
		fmt.Fprintf(w, "sk_lookup demo OK\n")
		fmt.Fprintf(w, "server_listen=%s\n", *listen)
		fmt.Fprintf(w, "http_local_addr=%v\n", local)
		fmt.Fprintf(w, "remote=%s\n", r.RemoteAddr)
		fmt.Fprintf(w, "host=%s\n", r.Host)
		fmt.Fprintf(w, "path=%s\n", r.URL.Path)
	})

	srv := &http.Server{Handler: mux}
	go func() {
		log.Printf("HTTP server serving on %s (and steered ports)", *listen)
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("serve: %v", err)
		}
	}()

	// Also print how to curl
	host, realPort, _ := net.SplitHostPort(*listen)
	if host == "" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	fmt.Println("======== DEMO READY ========")
	fmt.Printf("Real bind:   curl -sS http://%s:%s/\n", host, realPort)
	for _, p := range strings.Split(*extra, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		fmt.Printf("Steered:     curl -sS http://%s:%s/\n", host, p)
	}
	fmt.Println("Without BPF those steered ports would fail to connect.")
	fmt.Println("Ctrl+C to stop.")
	fmt.Println("============================")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}
