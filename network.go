package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	maxAutoHosts     = 4096
	maxExplicitHosts = 65534
)

type ScanOptions struct {
	CIDR          string
	InterfaceName string
	AllInterfaces bool
	Timeout       time.Duration
	Workers       int
	Ports         []int
}

type NetworkTarget struct {
	InterfaceName string
	CIDR          *net.IPNet
	IP            net.IP
	Flags         net.Flags
	HostCount     uint64
}

type Device struct {
	IP         string
	Name       string
	NameSource string
	SeenBy     []string
}

func discoverNetworkTargets(opts ScanOptions) ([]NetworkTarget, error) {
	switch {
	case opts.CIDR != "":
		target, err := targetFromCIDR(opts.CIDR)
		if err != nil {
			return nil, err
		}
		if target.HostCount > maxExplicitHosts {
			return nil, fmt.Errorf("%s has %d scan addresses; refusing ranges larger than %d", target.CIDR, target.HostCount, maxExplicitHosts)
		}
		return []NetworkTarget{target}, nil

	case opts.InterfaceName != "":
		iface, err := net.InterfaceByName(opts.InterfaceName)
		if err != nil {
			return nil, err
		}
		targets, err := targetsForInterface(*iface, false)
		if err != nil {
			return nil, err
		}
		if len(targets) == 0 {
			return nil, fmt.Errorf("interface %q has no usable IPv4 network", opts.InterfaceName)
		}
		return validateTargetSizes(targets, maxExplicitHosts)

	case opts.AllInterfaces:
		targets, err := collectInterfaceTargets(true)
		if err != nil {
			return nil, err
		}
		if len(targets) == 0 {
			return nil, fmt.Errorf("no active local-use IPv4 interfaces found")
		}
		return validateTargetSizes(dedupeTargets(targets), maxExplicitHosts)

	default:
		targets, err := collectInterfaceTargets(true)
		if err != nil {
			return nil, err
		}
		if len(targets) == 0 {
			return nil, fmt.Errorf("no active local-use IPv4 interfaces found")
		}

		best := chooseBestTarget(dedupeTargets(targets), outboundLocalIPv4())
		if best.HostCount > maxAutoHosts {
			return nil, fmt.Errorf("default target %s has %d scan addresses; use --cidr or --iface to scan it explicitly", best.CIDR, best.HostCount)
		}
		return []NetworkTarget{best}, nil
	}
}

func targetFromCIDR(raw string) (NetworkTarget, error) {
	ip, ipNet, err := net.ParseCIDR(strings.TrimSpace(raw))
	if err != nil {
		return NetworkTarget{}, fmt.Errorf("invalid --cidr: %w", err)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return NetworkTarget{}, fmt.Errorf("invalid --cidr: only IPv4 networks are supported")
	}

	normalized := normalizeIPv4Net(&net.IPNet{IP: ip4, Mask: ipNet.Mask})
	return NetworkTarget{
		CIDR:      normalized,
		HostCount: ipv4HostCount(normalized),
	}, nil
}

func collectInterfaceTargets(includeSuspicious bool) ([]NetworkTarget, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var targets []NetworkTarget
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if !includeSuspicious && isSuspiciousInterfaceName(iface.Name) {
			continue
		}

		ifaceTargets, err := targetsForInterface(iface, true)
		if err != nil {
			continue
		}
		targets = append(targets, ifaceTargets...)
	}

	return targets, nil
}

func targetsForInterface(iface net.Interface, localUseOnly bool) ([]NetworkTarget, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	var targets []NetworkTarget
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipNet.IP.To4()
		if ip4 == nil || ip4.IsLoopback() || isLinkLocalIPv4(ip4) {
			continue
		}
		if localUseOnly && !isLocalUseIPv4(ip4) {
			continue
		}

		normalized := normalizeIPv4Net(&net.IPNet{IP: ip4, Mask: ipNet.Mask})
		targets = append(targets, NetworkTarget{
			InterfaceName: iface.Name,
			CIDR:          normalized,
			IP:            cloneIP(ip4),
			Flags:         iface.Flags,
			HostCount:     ipv4HostCount(normalized),
		})
	}

	return targets, nil
}

func validateTargetSizes(targets []NetworkTarget, limit uint64) ([]NetworkTarget, error) {
	for _, target := range targets {
		if target.HostCount > limit {
			return nil, fmt.Errorf("%s has %d scan addresses; refusing ranges larger than %d", target.CIDR, target.HostCount, limit)
		}
	}
	return targets, nil
}

func dedupeTargets(targets []NetworkTarget) []NetworkTarget {
	seen := make(map[string]struct{}, len(targets))
	out := make([]NetworkTarget, 0, len(targets))
	for _, target := range targets {
		key := target.CIDR.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, target)
	}
	return out
}

func chooseBestTarget(targets []NetworkTarget, routeIP net.IP) NetworkTarget {
	sort.SliceStable(targets, func(i, j int) bool {
		leftScore := scoreTarget(targets[i], routeIP)
		rightScore := scoreTarget(targets[j], routeIP)
		if leftScore != rightScore {
			return leftScore > rightScore
		}
		if targets[i].HostCount != targets[j].HostCount {
			return targets[i].HostCount < targets[j].HostCount
		}
		return targets[i].CIDR.String() < targets[j].CIDR.String()
	})
	return targets[0]
}

func scoreTarget(target NetworkTarget, routeIP net.IP) int {
	score := 0
	if isPrivateIPv4(target.IP) {
		score += 100
	} else if isLocalUseIPv4(target.IP) {
		score += 20
	}
	if target.Flags&net.FlagBroadcast != 0 {
		score += 45
	}
	if target.Flags&net.FlagPointToPoint != 0 {
		score -= 140
	} else {
		score += 35
	}
	if isLikelyPhysicalInterfaceName(target.InterfaceName) {
		score += 35
	}
	if isSuspiciousInterfaceName(target.InterfaceName) {
		score -= 170
	}
	if routeIP4 := routeIP.To4(); routeIP4 != nil {
		if target.IP.Equal(routeIP4) {
			score += 70
		} else if target.CIDR.Contains(routeIP4) {
			score += 55
		}
	}
	if target.HostCount <= 254 {
		score += 20
	} else if target.HostCount > maxAutoHosts {
		score -= 40
	}
	return score
}

func outboundLocalIPv4() net.IP {
	conn, err := net.DialTimeout("udp4", "8.8.8.8:80", 200*time.Millisecond)
	if err != nil {
		return nil
	}
	defer conn.Close()

	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil
	}
	return addr.IP.To4()
}

func parsePorts(raw string) ([]int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	seen := make(map[int]struct{})
	var ports []int
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		port, err := strconv.Atoi(part)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid TCP port %q", part)
		}
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		ports = append(ports, port)
	}
	return ports, nil
}

func formatTargets(targets []NetworkTarget) string {
	parts := make([]string, 0, len(targets))
	for _, target := range targets {
		if target.InterfaceName == "" {
			parts = append(parts, target.CIDR.String())
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%s", target.InterfaceName, target.CIDR))
	}
	return strings.Join(parts, ", ")
}

func ipv4Hosts(ipNet *net.IPNet) []net.IP {
	start, end := ipv4Range(ipNet)
	hosts := make([]net.IP, 0, end-start+1)
	for current := start; current <= end; current++ {
		hosts = append(hosts, uint32ToIP(current))
		if current == end {
			break
		}
	}
	return hosts
}

func ipv4HostCount(ipNet *net.IPNet) uint64 {
	start, end := ipv4Range(ipNet)
	return uint64(end-start) + 1
}

func ipv4Range(ipNet *net.IPNet) (uint32, uint32) {
	ip := ipNet.IP.To4()
	mask := binary.BigEndian.Uint32(ipNet.Mask)
	network := binary.BigEndian.Uint32(ip) & mask
	broadcast := network | ^mask

	ones, bits := ipNet.Mask.Size()
	if bits == 32 && ones <= 30 {
		return network + 1, broadcast - 1
	}
	return network, broadcast
}

func normalizeIPv4Net(ipNet *net.IPNet) *net.IPNet {
	ip4 := ipNet.IP.To4()
	if ip4 == nil {
		return ipNet
	}
	network := cloneIP(ip4.Mask(ipNet.Mask))
	return &net.IPNet{IP: network, Mask: ipNet.Mask}
}

func cloneIP(ip net.IP) net.IP {
	out := make(net.IP, len(ip))
	copy(out, ip)
	return out
}

func ipToUint32(raw string) uint32 {
	ip := net.ParseIP(raw).To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

func uint32ToIP(value uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, value)
	return ip
}

func isPrivateIPv4(ip net.IP) bool {
	ip = ip.To4()
	return ip != nil && (ip[0] == 10 ||
		ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31 ||
		ip[0] == 192 && ip[1] == 168)
}

func isLocalUseIPv4(ip net.IP) bool {
	ip = ip.To4()
	return isPrivateIPv4(ip) ||
		ip != nil && ip[0] == 100 && ip[1] >= 64 && ip[1] <= 127 ||
		ip != nil && ip[0] == 198 && (ip[1] == 18 || ip[1] == 19)
}

func isLinkLocalIPv4(ip net.IP) bool {
	ip = ip.To4()
	return ip != nil && ip[0] == 169 && ip[1] == 254
}

func isLikelyPhysicalInterfaceName(name string) bool {
	name = strings.ToLower(name)
	return strings.HasPrefix(name, "en") ||
		strings.HasPrefix(name, "eth") ||
		strings.HasPrefix(name, "wlan") ||
		strings.HasPrefix(name, "wl") ||
		strings.Contains(name, "wi-fi") ||
		strings.Contains(name, "wifi") ||
		strings.Contains(name, "ethernet")
}

func isSuspiciousInterfaceName(name string) bool {
	name = strings.ToLower(name)
	prefixes := []string{
		"utun", "tun", "tap", "wg", "zt", "tailscale", "zerotier",
		"docker", "br-", "bridge", "vmnet", "vboxnet", "veth",
		"awdl", "llw", "anpi",
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
