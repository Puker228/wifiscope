package main

import (
	"encoding/binary"
	"net"
	"reflect"
	"testing"
)

func mustCIDR(t *testing.T, raw string) *net.IPNet {
	t.Helper()
	_, ipNet, err := net.ParseCIDR(raw)
	if err != nil {
		t.Fatal(err)
	}
	return normalizeIPv4Net(ipNet)
}

func TestIPv4HostsUsesRealMask(t *testing.T) {
	hosts := ipv4Hosts(mustCIDR(t, "192.168.10.0/30"))
	got := make([]string, 0, len(hosts))
	for _, host := range hosts {
		got = append(got, host.String())
	}

	want := []string{"192.168.10.1", "192.168.10.2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("hosts = %v, want %v", got, want)
	}
}

func TestIPv4HostsIncludes31Endpoints(t *testing.T) {
	hosts := ipv4Hosts(mustCIDR(t, "192.168.10.0/31"))
	got := make([]string, 0, len(hosts))
	for _, host := range hosts {
		got = append(got, host.String())
	}

	want := []string{"192.168.10.0", "192.168.10.1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("hosts = %v, want %v", got, want)
	}
}

func TestChooseBestTargetAvoidsVPNWhenLANExists(t *testing.T) {
	lan := NetworkTarget{
		InterfaceName: "en0",
		CIDR:          mustCIDR(t, "192.168.31.0/24"),
		IP:            net.ParseIP("192.168.31.146").To4(),
		Flags:         net.FlagUp | net.FlagBroadcast,
		HostCount:     254,
	}
	vpn := NetworkTarget{
		InterfaceName: "utun6",
		CIDR:          mustCIDR(t, "198.18.0.0/24"),
		IP:            net.ParseIP("198.18.0.1").To4(),
		Flags:         net.FlagUp | net.FlagPointToPoint,
		HostCount:     254,
	}

	got := chooseBestTarget([]NetworkTarget{vpn, lan}, net.ParseIP("198.18.0.1"))
	if got.InterfaceName != "en0" {
		t.Fatalf("best interface = %q, want en0", got.InterfaceName)
	}
}

func TestParsePortsDedupesAndValidates(t *testing.T) {
	got, err := parsePorts("22, 80,22,443")
	if err != nil {
		t.Fatal(err)
	}
	want := []int{22, 80, 443}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ports = %v, want %v", got, want)
	}

	if _, err := parsePorts("22,70000"); err == nil {
		t.Fatal("expected invalid port error")
	}
}

func TestTargetFromCIDRDoesNotInventLocalIP(t *testing.T) {
	target, err := targetFromCIDR("192.168.31.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if target.IP != nil {
		t.Fatalf("explicit CIDR target IP = %v, want nil", target.IP)
	}
	if got, want := target.CIDR.String(), "192.168.31.0/24"; got != want {
		t.Fatalf("cidr = %q, want %q", got, want)
	}
}

func TestDeviceMergePriority(t *testing.T) {
	device := &Device{IP: "192.168.1.20"}
	addSeen(device, "tcp:80,icmp")
	addSeen(device, "icmp")
	setDeviceName(device, "DESKTOP", "netbios")
	setDeviceName(device, "desktop.local", "mdns")
	setDeviceName(device, "router.example", "rdns")

	if got, want := device.Name, "router.example"; got != want {
		t.Fatalf("name = %q, want %q", got, want)
	}
	if got, want := device.NameSource, "rdns"; got != want {
		t.Fatalf("name source = %q, want %q", got, want)
	}
	if got, want := device.SeenBy, []string{"icmp", "tcp:80"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("seenBy = %v, want %v", got, want)
	}
}

func TestIPToUint32SortValue(t *testing.T) {
	ip := net.ParseIP("192.168.1.10").To4()
	want := binary.BigEndian.Uint32(ip)
	if got := ipToUint32("192.168.1.10"); got != want {
		t.Fatalf("ip value = %d, want %d", got, want)
	}
}
