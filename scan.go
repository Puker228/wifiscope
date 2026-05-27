package main

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-ping/ping"
)

type probeResult struct {
	Seen       bool
	SeenBy     string
	Name       string
	NameSource string
}

func scanNetworks(targets []NetworkTarget, opts ScanOptions) ([]Device, error) {
	results := make(map[string]*Device)
	var mu sync.Mutex

	merge := func(ip string, result probeResult) {
		if ip == "" {
			return
		}

		mu.Lock()
		defer mu.Unlock()

		device := results[ip]
		if device == nil {
			device = &Device{IP: ip}
			results[ip] = device
		}
		if result.SeenBy != "" {
			addSeen(device, result.SeenBy)
		}
		if result.Name != "" {
			setDeviceName(device, result.Name, result.NameSource)
		}
	}

	for _, target := range targets {
		if target.IP != nil {
			hostname, _ := os.Hostname()
			merge(target.IP.String(), probeResult{
				Seen:       true,
				SeenBy:     "local",
				Name:       cleanDeviceName(hostname),
				NameSource: "local",
			})
		}
	}

	for _, ip := range neighborIPsInTargets(targets) {
		merge(ip, probeResult{Seen: true, SeenBy: "neighbor"})
	}

	jobs := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < opts.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				device := scanIP(ip, opts)
				if device == nil {
					continue
				}
				merge(device.IP, probeResult{
					Seen:       len(device.SeenBy) > 0,
					SeenBy:     strings.Join(device.SeenBy, ","),
					Name:       device.Name,
					NameSource: device.NameSource,
				})
			}
		}()
	}

	queued := make(map[string]struct{})
	for _, target := range targets {
		for _, ip := range ipv4Hosts(target.CIDR) {
			ipText := ip.String()
			if _, ok := queued[ipText]; ok {
				continue
			}
			queued[ipText] = struct{}{}
			jobs <- ipText
		}
	}
	close(jobs)
	wg.Wait()

	for _, ip := range neighborIPsInTargets(targets) {
		merge(ip, probeResult{Seen: true, SeenBy: "neighbor"})
	}

	devices := make([]Device, 0, len(results))
	for _, device := range results {
		devices = append(devices, *device)
	}
	sort.Slice(devices, func(i, j int) bool {
		return ipToUint32(devices[i].IP) < ipToUint32(devices[j].IP)
	})
	return devices, nil
}

func scanIP(ip string, opts ScanOptions) *Device {
	probes := []func(string, ScanOptions) probeResult{
		probeICMP,
		probeTCP,
		probeReverseDNS,
		probeMDNS,
		probeLLMNR,
		probeNetBIOS,
	}

	results := make(chan probeResult, len(probes))
	var wg sync.WaitGroup
	for _, probe := range probes {
		wg.Add(1)
		go func(probe func(string, ScanOptions) probeResult) {
			defer wg.Done()
			results <- probe(ip, opts)
		}(probe)
	}
	wg.Wait()
	close(results)

	device := &Device{IP: ip}
	for result := range results {
		if result.Seen && result.SeenBy != "" {
			addSeen(device, result.SeenBy)
		}
		if result.Name != "" {
			setDeviceName(device, result.Name, result.NameSource)
		}
	}
	if len(device.SeenBy) == 0 && device.Name == "" {
		return nil
	}
	return device
}

func probeICMP(ip string, opts ScanOptions) probeResult {
	alive, failed := pingOnce(ip, opts.Timeout, runtime.GOOS == "windows")
	if alive {
		return probeResult{Seen: true, SeenBy: "icmp"}
	}
	if runtime.GOOS == "windows" || !failed {
		return probeResult{}
	}

	alive, _ = pingOnce(ip, opts.Timeout, true)
	if alive {
		return probeResult{Seen: true, SeenBy: "icmp"}
	}
	return probeResult{}
}

func pingOnce(ip string, timeout time.Duration, privileged bool) (bool, bool) {
	pinger, err := ping.NewPinger(ip)
	if err != nil {
		return false, true
	}
	pinger.SetLogger(ping.NoopLogger{})
	pinger.SetPrivileged(privileged)
	pinger.Count = 1
	pinger.Timeout = timeout
	pinger.Interval = timeout
	if err := pinger.Run(); err != nil {
		return false, true
	}
	return pinger.Statistics().PacketsRecv > 0, false
}

func probeTCP(ip string, opts ScanOptions) probeResult {
	if len(opts.Ports) == 0 {
		return probeResult{}
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()

	found := make(chan string, len(opts.Ports))
	var wg sync.WaitGroup
	for _, port := range opts.Ports {
		port := port
		wg.Add(1)
		go func() {
			defer wg.Done()
			address := net.JoinHostPort(ip, strconv.Itoa(port))
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp4", address)
			if err == nil {
				_ = conn.Close()
				found <- "tcp:" + strconv.Itoa(port)
				return
			}
			if isConnectionRefused(err) {
				found <- "tcp:" + strconv.Itoa(port)
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case source := <-found:
		cancel()
		return probeResult{Seen: true, SeenBy: source}
	case <-done:
		return probeResult{}
	case <-ctx.Done():
		return probeResult{}
	}
}

func isConnectionRefused(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "connection refused") ||
		strings.Contains(lower, "actively refused")
}

func probeReverseDNS(ip string, opts ScanOptions) probeResult {
	ch := make(chan string, 1)
	go func() {
		ch <- lookupReverseDNSName(ip)
	}()

	select {
	case name := <-ch:
		if name == "" {
			return probeResult{}
		}
		return probeResult{Seen: true, SeenBy: "rdns", Name: name, NameSource: "rdns"}
	case <-time.After(opts.Timeout):
		return probeResult{}
	}
}

func probeMDNS(ip string, opts ScanOptions) probeResult {
	name, ok := lookupPTRMulticastName(ip, net.IPv4(224, 0, 0, 251), 5353, 0x8001, opts.Timeout)
	if !ok {
		return probeResult{}
	}
	return probeResult{Seen: true, SeenBy: "mdns", Name: name, NameSource: "mdns"}
}

func probeLLMNR(ip string, opts ScanOptions) probeResult {
	name, ok := lookupPTRMulticastName(ip, net.IPv4(224, 0, 0, 252), 5355, 0x0001, opts.Timeout)
	if !ok {
		return probeResult{}
	}
	return probeResult{Seen: true, SeenBy: "llmnr", Name: name, NameSource: "llmnr"}
}

func probeNetBIOS(ip string, opts ScanOptions) probeResult {
	name, ok := lookupNetBIOSName(ip, opts.Timeout)
	if !ok {
		return probeResult{}
	}
	return probeResult{Seen: true, SeenBy: "netbios", Name: name, NameSource: "netbios"}
}

func addSeen(device *Device, source string) {
	for _, part := range strings.Split(source, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		found := false
		for _, existing := range device.SeenBy {
			if existing == part {
				found = true
				break
			}
		}
		if !found {
			device.SeenBy = append(device.SeenBy, part)
		}
	}
	sort.Strings(device.SeenBy)
}

func setDeviceName(device *Device, name string, source string) {
	name = cleanDeviceName(name)
	if name == "" {
		return
	}
	if device.Name == "" || nameSourceRank(source) < nameSourceRank(device.NameSource) {
		device.Name = name
		device.NameSource = source
	}
}

func nameSourceRank(source string) int {
	switch source {
	case "local":
		return 0
	case "rdns":
		return 1
	case "mdns":
		return 2
	case "llmnr":
		return 3
	case "netbios":
		return 4
	default:
		return 99
	}
}

func neighborIPsInTargets(targets []NetworkTarget) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	candidates := readNeighborIPs(ctx)
	seen := make(map[string]struct{})
	var out []string
	for _, ip := range candidates {
		parsed := net.ParseIP(ip).To4()
		if parsed == nil {
			continue
		}
		for _, target := range targets {
			if target.CIDR.Contains(parsed) {
				if _, ok := seen[ip]; !ok {
					seen[ip] = struct{}{}
					out = append(out, ip)
				}
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return ipToUint32(out[i]) < ipToUint32(out[j])
	})
	return out
}

func readNeighborIPs(ctx context.Context) []string {
	var outputs []string
	switch runtime.GOOS {
	case "linux":
		outputs = append(outputs, commandOutput(ctx, "ip", "neigh"))
		outputs = append(outputs, commandOutput(ctx, "arp", "-a"))
	default:
		outputs = append(outputs, commandOutput(ctx, "arp", "-a"))
	}

	seen := make(map[string]struct{})
	var ips []string
	for _, output := range outputs {
		for _, ip := range parseNeighborIPs(output) {
			if _, ok := seen[ip]; ok {
				continue
			}
			seen[ip] = struct{}{}
			ips = append(ips, ip)
		}
	}
	return ips
}

func commandOutput(ctx context.Context, name string, args ...string) string {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return string(out)
}

func parseNeighborIPs(output string) []string {
	fields := strings.FieldsFunc(output, func(r rune) bool {
		return !(r == '.' || r >= '0' && r <= '9')
	})

	seen := make(map[string]struct{})
	var ips []string
	for _, field := range fields {
		ip := net.ParseIP(field).To4()
		if ip == nil || ip.IsLoopback() || ip.IsMulticast() || isLinkLocalIPv4(ip) {
			continue
		}
		text := ip.String()
		if _, ok := seen[text]; ok {
			continue
		}
		seen[text] = struct{}{}
		ips = append(ips, text)
	}
	return ips
}
