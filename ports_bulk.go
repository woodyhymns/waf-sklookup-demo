package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
)

const defaultBulkBatch = 4096

// Must match dispatch.bpf.c open_ports max_entries. 1024 blocked M3 30K/60K fills.
const openPortsMaxEntries = 131072

type bulkResult struct {
	N         int
	Elapsed   time.Duration
	UsedBatch bool
	Missing   int
}

func loadPinnedOpenPorts(pinDir string) (*ebpf.Map, error) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, "open_ports"), nil)
	if err != nil {
		return nil, fmt.Errorf("load pinned open_ports: %w (is the loader still running?)", err)
	}
	return m, nil
}

func bulkPutPorts(m *ebpf.Map, ports []uint16, slot uint8, batchSize int, progress io.Writer) (bulkResult, error) {
	var res bulkResult
	if len(ports) == 0 {
		return res, nil
	}
	if batchSize <= 0 {
		batchSize = defaultBulkBatch
	}
	start := time.Now()
	useBatch := true
	done := 0
	for i := 0; i < len(ports); {
		end := i + batchSize
		if end > len(ports) {
			end = len(ports)
		}
		chunk := ports[i:end]
		if useBatch {
			vals := make([]uint8, len(chunk))
			for j := range vals {
				vals[j] = slot
			}
			n, err := m.BatchUpdate(chunk, vals, nil)
			if err != nil {
				if done == 0 {
					log.Printf("BPF batch update unavailable (%v); falling back to per-key put (still O(n))", err)
					useBatch = false
					continue
				}
				res.N = done
				res.Elapsed = time.Since(start)
				res.UsedBatch = true
				return res, fmt.Errorf("batch update at offset %d: %w", i, err)
			}
			done += n
			res.UsedBatch = true
		} else {
			for _, p := range chunk {
				if err := m.Put(p, slot); err != nil {
					res.N = done
					res.Elapsed = time.Since(start)
					return res, fmt.Errorf("put port %d: %w", p, err)
				}
				done++
			}
		}
		i = end
		reportBulkProgress(progress, "add", done, len(ports), start)
	}
	res.N = done
	res.Elapsed = time.Since(start)
	return res, nil
}

func bulkDeletePorts(m *ebpf.Map, ports []uint16, batchSize int, progress io.Writer) (bulkResult, error) {
	var res bulkResult
	if len(ports) == 0 {
		return res, nil
	}
	if batchSize <= 0 {
		batchSize = defaultBulkBatch
	}
	start := time.Now()
	// Per-key delete keeps "already closed" semantics. 60K deletes are still O(n)
	// syscalls (no map-wide walk per port). BatchDelete is used when every key exists;
	// on any error the chunk falls back to per-key.
	done := 0
	for i := 0; i < len(ports); {
		end := i + batchSize
		if end > len(ports) {
			end = len(ports)
		}
		chunk := ports[i:end]
		n, err := m.BatchDelete(chunk, nil)
		if err == nil {
			done += n
			res.UsedBatch = true
		} else {
			for _, p := range chunk {
				if err := m.Delete(p); err != nil {
					if errors.Is(err, ebpf.ErrKeyNotExist) {
						res.Missing++
						done++
						continue
					}
					res.N = done
					res.Elapsed = time.Since(start)
					return res, fmt.Errorf("delete port %d: %w", p, err)
				}
				done++
			}
		}
		i = end
		reportBulkProgress(progress, "remove", done, len(ports), start)
	}
	res.N = done
	res.Elapsed = time.Since(start)
	return res, nil
}

func reportBulkProgress(w io.Writer, op string, done, total int, start time.Time) {
	if w == nil || total == 0 {
		return
	}
	// Skip noisy progress for tiny edits; bulk 30K/60K prints each batch.
	if total < 256 && done < total {
		return
	}
	elapsed := time.Since(start)
	pct := float64(done) * 100 / float64(total)
	rate := ""
	if elapsed > 0 {
		rate = fmt.Sprintf(" rate=%.0f/s", float64(done)/elapsed.Seconds())
	}
	fmt.Fprintf(w, "%s %d/%d (%.1f%%) elapsed=%s%s\n", op, done, total, pct, elapsed.Round(time.Millisecond), rate)
}

func formatBulkSummary(op string, n int, slot uint8, res bulkResult) string {
	label := "primary"
	if slot == uint8(redirTLS) {
		label = "tls-fallback"
	}
	extra := ""
	if res.Missing > 0 {
		extra = fmt.Sprintf(" missing=%d", res.Missing)
	}
	batch := "per-key"
	if res.UsedBatch {
		batch = "batch"
	}
	return fmt.Sprintf("%s n=%d slot=%d (%s) elapsed=%s method=%s%s",
		op, n, slot, label, res.Elapsed.Round(time.Millisecond), batch, extra)
}

func formatRemoveSummary(res bulkResult) string {
	extra := ""
	if res.Missing > 0 {
		extra = fmt.Sprintf(" missing=%d", res.Missing)
	}
	batch := "per-key"
	if res.UsedBatch {
		batch = "batch"
	}
	return fmt.Sprintf("removed n=%d elapsed=%s method=%s%s",
		res.N, res.Elapsed.Round(time.Millisecond), batch, extra)
}
