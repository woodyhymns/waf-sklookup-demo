// httpbench — minimal HTTP/HTTPS CPS + latency percentile bench (no wrk/ab).
// Used by production Go/No-Go P0 scripts.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	var (
		url        = flag.String("url", "http://127.0.0.1:18081/", "target URL")
		duration   = flag.Duration("d", 5*time.Second, "test duration")
		concurrency = flag.Int("c", 50, "concurrency")
		keepalive  = flag.Bool("keepalive", false, "reuse connections (long-conn mode)")
		insecure   = flag.Bool("k", true, "skip TLS verify")
		timeout    = flag.Duration("timeout", 5*time.Second, "per-request timeout")
		label      = flag.String("label", "", "optional label printed in RESULT line")
	)
	flag.Parse()

	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   2 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          *concurrency * 2,
		MaxIdleConnsPerHost:   *concurrency * 2,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableKeepAlives:     !*keepalive,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: *insecure, //nolint:gosec // demo/acceptance only
		},
	}
	client := &http.Client{Transport: tr, Timeout: *timeout}

	var (
		ok    atomic.Int64
		fail  atomic.Int64
		bytes atomic.Int64
		mu    sync.Mutex
		lats  []time.Duration
	)

	deadline := time.Now().Add(*duration)
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				t0 := time.Now()
				resp, err := client.Get(*url)
				elapsed := time.Since(t0)
				if err != nil {
					fail.Add(1)
					continue
				}
				n, _ := io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				bytes.Add(n)
				if resp.StatusCode >= 200 && resp.StatusCode < 400 {
					ok.Add(1)
					mu.Lock()
					lats = append(lats, elapsed)
					mu.Unlock()
				} else {
					fail.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	wall := time.Since(start)

	mu.Lock()
	sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })
	p := func(pct float64) time.Duration {
		if len(lats) == 0 {
			return 0
		}
		idx := int(float64(len(lats)-1) * pct)
		if idx < 0 {
			idx = 0
		}
		if idx >= len(lats) {
			idx = len(lats) - 1
		}
		return lats[idx]
	}
	p50, p90, p99, pmax := p(0.50), p(0.90), p(0.99), time.Duration(0)
	if len(lats) > 0 {
		pmax = lats[len(lats)-1]
	}
	mu.Unlock()

	oks := ok.Load()
	fails := fail.Load()
	total := oks + fails
	rps := float64(oks) / wall.Seconds()
	lbl := *label
	if lbl == "" {
		lbl = *url
	}
	mode := "short"
	if *keepalive {
		mode = "keepalive"
	}

	fmt.Printf("RESULT label=%s mode=%s url=%s c=%d d=%s wall=%s ok=%d fail=%d total=%d rps=%.1f p50_us=%d p90_us=%d p99_us=%d max_us=%d bytes=%d\n",
		lbl, mode, *url, *concurrency, duration.String(), wall.Truncate(time.Millisecond),
		oks, fails, total, rps,
		p50.Microseconds(), p90.Microseconds(), p99.Microseconds(), pmax.Microseconds(),
		bytes.Load(),
	)
	if oks == 0 {
		os.Exit(2)
	}
}
