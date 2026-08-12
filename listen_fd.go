package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// findListenSocketFile locates a LISTEN socket for host:port and returns a dup FD via /proc/pid/fd.
func findListenSocketFile(host string, port uint16) (*os.File, error) {
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("invalid host %q", host)
	}
	ip = ip.To4()
	if ip == nil {
		return nil, fmt.Errorf("only IPv4 supported for discovery, got %q", host)
	}

	data, err := os.ReadFile("/proc/net/tcp")
	if err != nil {
		return nil, err
	}
	inode, err := parseListenInode(string(data), ip, port)
	if err != nil {
		anyIP := net.IPv4(0, 0, 0, 0).To4()
		inode, err = parseListenInode(string(data), anyIP, port)
		if err != nil {
			return nil, fmt.Errorf("no LISTEN socket for %s:%d: %w", ip, port, err)
		}
	}
	f, err := openSocketByInode(inode)
	if err != nil {
		return nil, err
	}
	log.Printf("discovered listen socket inode=%d for %s:%d", inode, ip, port)
	return f, nil
}

func parseListenInode(table string, ip net.IP, port uint16) (uint64, error) {
	wantPort := fmt.Sprintf("%04X", port)
	wantAddr := fmt.Sprintf("%08X", ipToProcHex(ip))
	lines := strings.Split(table, "\n")
	if len(lines) == 0 {
		return 0, fmt.Errorf("empty /proc/net/tcp")
	}
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		local := fields[1]
		state := fields[3]
		if state != "0A" { // LISTEN
			continue
		}
		addr, portHex, ok := strings.Cut(local, ":")
		if !ok {
			continue
		}
		if !strings.EqualFold(portHex, wantPort) || !strings.EqualFold(addr, wantAddr) {
			continue
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			continue
		}
		return inode, nil
	}
	return 0, fmt.Errorf("no LISTEN socket for %s:%d", ip, port)
}

func ipToProcHex(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0]) | uint32(ip[1])<<8 | uint32(ip[2])<<16 | uint32(ip[3])<<24
}

func openSocketByInode(inode uint64) (*os.File, error) {
	want := fmt.Sprintf("socket:[%d]", inode)
	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, ent := range procEntries {
		if !isPidName(ent.Name()) {
			continue
		}
		pid, err := strconv.Atoi(ent.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join("/proc", ent.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fdent := range fds {
			path := filepath.Join(fdDir, fdent.Name())
			target, err := os.Readlink(path)
			if err != nil || target != want {
				continue
			}
			fdNum, err := strconv.Atoi(fdent.Name())
			if err != nil {
				continue
			}
			f, err := dupForeignSocket(pid, fdNum, want)
			if err != nil {
				lastErr = err
				continue
			}
			return f, nil
		}
	}
	if lastErr != nil {
		return nil, fmt.Errorf("socket inode %d found but dup failed: %w", inode, lastErr)
	}
	return nil, fmt.Errorf("socket inode %d not found under /proc/*/fd", inode)
}

// dupForeignSocket copies another process's FD into this process.
// open(/proc/pid/fd/N) returns ENXIO for sockets on some kernels; pidfd_getfd works (Linux ≥ 5.6).
func dupForeignSocket(pid, fd int, name string) (*os.File, error) {
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return nil, fmt.Errorf("pidfd_open(%d): %w", pid, err)
	}
	defer unix.Close(pidfd)
	sockfd, err := unix.PidfdGetfd(pidfd, fd, 0)
	if err != nil {
		return nil, fmt.Errorf("pidfd_getfd(pid=%d fd=%d): %w", pid, fd, err)
	}
	return os.NewFile(uintptr(sockfd), name), nil
}

func isPidName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		if name[i] < '0' || name[i] > '9' {
			return false
		}
	}
	return true
}
