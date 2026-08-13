package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

const ctlUsage = `M2 control plane (pinned open_ports; no OpenResty reload):

  sudo ./waf-sklookup-demo add PORT[,PORT|START-END...] [-tls] [-pin-dir DIR]
  sudo ./waf-sklookup-demo remove PORT[,PORT|START-END...] [-pin-dir DIR]
  sudo ./waf-sklookup-demo list [-count] [-pin-dir DIR]
  sudo ./waf-sklookup-demo bulk add -range START-END [-tls] [-pin-dir DIR]
  sudo ./waf-sklookup-demo bulk add -file ports.txt [-tls]
  sudo ./waf-sklookup-demo bulk add -stdin [-tls] < ports.txt
  sudo ./waf-sklookup-demo bulk remove -range START-END
  sudo ./waf-sklookup-demo bulk fill -count 30000 [-start 5000]   # M3 seed

Aliases: open=add, close=remove, dump=list.
Legacy flags still work: -mode open-port|close-port|dump-ports.

Bulk is the M3 path for 30K / 60K map fills (range/file/stdin, batched puts,
progress + timing). Do not pass tens of thousands of ports on loader startup.
`

func isCtlCommand(s string) bool {
	switch s {
	case "add", "open", "remove", "close", "list", "dump", "bulk", "help":
		return true
	default:
		return false
	}
}

func runCtl(args []string) error {
	if len(args) == 0 {
		return errors.New(strings.TrimSpace(ctlUsage))
	}
	switch args[0] {
	case "add", "open":
		return ctlAdd(args[1:])
	case "remove", "close":
		return ctlRemove(args[1:])
	case "list", "dump":
		return ctlList(args[1:])
	case "bulk":
		return ctlBulk(args[1:])
	case "help":
		fmt.Fprint(os.Stderr, ctlUsage)
		return nil
	default:
		return fmt.Errorf("unknown command %q\n%s", args[0], ctlUsage)
	}
}

func newPinFlagSet(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	pinDir := fs.String("pin-dir", defaultPinDir, "bpffs directory with pinned open_ports")
	return fs, pinDir
}

func ctlSlot(tls bool) uint8 {
	if tls {
		return uint8(redirTLS)
	}
	return uint8(redirPrimary)
}

func ctlAdd(args []string) error {
	fs, pinDir := newPinFlagSet("add")
	tls := fs.Bool("tls", false, "stock TLS fallback sockmap slot 1 (not the Tengine product path)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ports, err := portsFromArgs(fs.Args())
	if err != nil {
		return err
	}
	if len(ports) == 0 {
		return errors.New("add needs PORT[,PORT...] or START-END")
	}
	return applyAdd(*pinDir, ports, ctlSlot(*tls), defaultBulkBatch, os.Stderr, len(ports) > 32)
}

func ctlRemove(args []string) error {
	fs, pinDir := newPinFlagSet("remove")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ports, err := portsFromArgs(fs.Args())
	if err != nil {
		return err
	}
	if len(ports) == 0 {
		return errors.New("remove needs PORT[,PORT...] or START-END")
	}
	return applyRemove(*pinDir, ports, defaultBulkBatch, os.Stderr, len(ports) > 32)
}

func ctlList(args []string) error {
	fs, pinDir := newPinFlagSet("list")
	countOnly := fs.Bool("count", false, "print only the number of keys (useful at 30K/60K)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return listPinnedPorts(*pinDir, os.Stdout, *countOnly)
}

func ctlBulk(args []string) error {
	if len(args) == 0 {
		return errors.New("bulk needs add | remove | fill")
	}
	switch args[0] {
	case "add":
		return ctlBulkAdd(args[1:])
	case "remove":
		return ctlBulkRemove(args[1:])
	case "fill":
		return ctlBulkFill(args[1:])
	default:
		return fmt.Errorf("unknown bulk command %q (want add, remove, fill)", args[0])
	}
}

func ctlBulkAdd(args []string) error {
	fs, pinDir := newPinFlagSet("bulk add")
	tls := fs.Bool("tls", false, "stock TLS fallback sockmap slot 1")
	rangeSpec := fs.String("range", "", "inclusive port range START-END (e.g. 10000-39999)")
	filePath := fs.String("file", "", "file of ports / ranges (one token or comma-list per line)")
	fromStdin := fs.Bool("stdin", false, "read ports from stdin")
	batch := fs.Int("batch", defaultBulkBatch, "BPF update chunk size")
	quiet := fs.Bool("quiet", false, "suppress progress on stderr")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ports, err := collectBulkPorts(*rangeSpec, *filePath, *fromStdin, fs.Args())
	if err != nil {
		return err
	}
	progress := bulkProgressWriter(*quiet)
	return applyAdd(*pinDir, ports, ctlSlot(*tls), *batch, progress, true)
}

func ctlBulkRemove(args []string) error {
	fs, pinDir := newPinFlagSet("bulk remove")
	rangeSpec := fs.String("range", "", "inclusive port range START-END")
	filePath := fs.String("file", "", "file of ports / ranges")
	fromStdin := fs.Bool("stdin", false, "read ports from stdin")
	batch := fs.Int("batch", defaultBulkBatch, "delete chunk size")
	quiet := fs.Bool("quiet", false, "suppress progress on stderr")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ports, err := collectBulkPorts(*rangeSpec, *filePath, *fromStdin, fs.Args())
	if err != nil {
		return err
	}
	progress := bulkProgressWriter(*quiet)
	return applyRemove(*pinDir, ports, *batch, progress, true)
}

func ctlBulkFill(args []string) error {
	fs, pinDir := newPinFlagSet("bulk fill")
	tls := fs.Bool("tls", false, "stock TLS fallback sockmap slot 1")
	count := fs.Int("count", 0, "how many ports to insert (M3: 30000 or 60000)")
	start := fs.Uint("start", 5000, "first port to try (default 5000 so a 60K fill fits in uint16; skips -skip)")
	skipRaw := fs.String("skip", "8080,8443", "comma-separated ports to leave out (internal listens)")
	batch := fs.Int("batch", defaultBulkBatch, "BPF update chunk size")
	quiet := fs.Bool("quiet", false, "suppress progress on stderr")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *start > 65535 {
		return fmt.Errorf("fill -start %d out of range", *start)
	}
	skip, err := parseSkipSet(*skipRaw)
	if err != nil {
		return err
	}
	ports, err := generateFillPorts(uint16(*start), *count, skip)
	if err != nil {
		return err
	}
	progress := bulkProgressWriter(*quiet)
	fmt.Fprintf(os.Stderr, "M3 fill: count=%d start=%d skip=%q pin=%s (no OpenResty reload)\n",
		*count, *start, *skipRaw, *pinDir)
	return applyAdd(*pinDir, ports, ctlSlot(*tls), *batch, progress, true)
}

func bulkProgressWriter(quiet bool) io.Writer {
	if quiet {
		return nil
	}
	return os.Stderr
}

func portsFromArgs(args []string) ([]uint16, error) {
	var out []uint16
	for _, a := range args {
		ports, err := parsePortListFlexible(a)
		if err != nil {
			return nil, err
		}
		out = append(out, ports...)
	}
	return uniquePorts(out), nil
}

func collectBulkPorts(rangeSpec, filePath string, fromStdin bool, extra []string) ([]uint16, error) {
	var out []uint16
	if rangeSpec != "" {
		ports, err := parsePortRange(rangeSpec)
		if err != nil {
			return nil, err
		}
		out = append(out, ports...)
	}
	if filePath != "" {
		f, err := os.Open(filePath)
		if err != nil {
			return nil, err
		}
		ports, err := loadPortsFromReader(f)
		_ = f.Close()
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", filePath, err)
		}
		out = append(out, ports...)
	}
	if fromStdin {
		ports, err := loadPortsFromReader(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("stdin: %w", err)
		}
		out = append(out, ports...)
	}
	extraPorts, err := portsFromArgs(extra)
	if err != nil {
		return nil, err
	}
	out = append(out, extraPorts...)
	out = uniquePorts(out)
	if len(out) == 0 {
		return nil, errors.New("bulk needs -range, -file, -stdin, and/or positional ports")
	}
	if len(out) > openPortsMaxEntries {
		return nil, fmt.Errorf("bulk list has %d ports; open_ports max_entries is %d", len(out), openPortsMaxEntries)
	}
	return out, nil
}

func applyAdd(pinDir string, ports []uint16, slot uint8, batch int, progress io.Writer, summary bool) error {
	m, err := loadPinnedOpenPorts(pinDir)
	if err != nil {
		return err
	}
	defer m.Close()
	res, err := bulkPutPorts(m, ports, slot, batch, progress)
	if err != nil {
		return err
	}
	if summary {
		fmt.Println(formatBulkSummary("added", res.N, slot, res))
		return nil
	}
	label := ""
	if slot == uint8(redirTLS) {
		label = " (stock TLS fallback)"
	}
	for _, p := range ports {
		fmt.Printf("opened steered port %d → redir_socket[%d]%s\n", p, slot, label)
	}
	return nil
}

func applyRemove(pinDir string, ports []uint16, batch int, progress io.Writer, summary bool) error {
	m, err := loadPinnedOpenPorts(pinDir)
	if err != nil {
		return err
	}
	defer m.Close()
	res, err := bulkDeletePorts(m, ports, batch, progress)
	if err != nil {
		return err
	}
	if summary {
		fmt.Println(formatRemoveSummary(res))
		return nil
	}
	for _, p := range ports {
		fmt.Printf("closed steered port %d (removed from open_ports)\n", p)
	}
	if res.Missing > 0 {
		fmt.Fprintf(os.Stderr, "note: %d port(s) were already absent from the map\n", res.Missing)
	}
	return nil
}
