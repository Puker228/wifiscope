package main

import (
	"encoding/binary"
	"reflect"
	"testing"
)

func TestParseNeighborIPs(t *testing.T) {
	output := `
? (192.168.31.1) at 5c:2:14:b5:2f:98 on en0 ifscope [ethernet]
192.168.31.45 dev wlan0 lladdr e6:37:08:20:5d:d4 REACHABLE
  192.168.31.83          ec-31-4a-5e-13-ec     dynamic
  169.254.1.1            aa-bb-cc-dd-ee-ff     dynamic
`

	got := parseNeighborIPs(output)
	want := []string{"192.168.31.1", "192.168.31.45", "192.168.31.83"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ips = %v, want %v", got, want)
	}
}

func TestParseDNSPTRResponse(t *testing.T) {
	wanted := "2.1.168.192.in-addr.arpa"
	msg := buildDNSQuery(wanted, 12, 1)
	binary.BigEndian.PutUint16(msg[6:8], 1)

	msg = append(msg, 0xC0, 0x0C)
	msg = binary.BigEndian.AppendUint16(msg, 12)
	msg = binary.BigEndian.AppendUint16(msg, 1)
	msg = binary.BigEndian.AppendUint32(msg, 120)
	ptr := encodeDNSName("macbook.local")
	msg = binary.BigEndian.AppendUint16(msg, uint16(len(ptr)))
	msg = append(msg, ptr...)

	if got, want := parseDNSPTRResponse(msg, wanted), "macbook.local"; got != want {
		t.Fatalf("ptr = %q, want %q", got, want)
	}
}

func TestParseNetBIOSNodeStatusResponse(t *testing.T) {
	var msg []byte
	msg = make([]byte, 12)
	binary.BigEndian.PutUint16(msg[6:8], 1)

	msg = append(msg, encodeNetBIOSName("*")...)
	msg = binary.BigEndian.AppendUint16(msg, 0x0021)
	msg = binary.BigEndian.AppendUint16(msg, 0x0001)
	msg = binary.BigEndian.AppendUint32(msg, 0)

	rdata := []byte{1}
	name := []byte("DESKTOP")
	for len(name) < 15 {
		name = append(name, ' ')
	}
	rdata = append(rdata, name...)
	rdata = append(rdata, 0x00)
	rdata = binary.BigEndian.AppendUint16(rdata, 0x0000)

	msg = binary.BigEndian.AppendUint16(msg, uint16(len(rdata)))
	msg = append(msg, rdata...)

	if got, want := parseNetBIOSNodeStatusResponse(msg), "DESKTOP"; got != want {
		t.Fatalf("netbios name = %q, want %q", got, want)
	}
}

func TestReverseIPv4Name(t *testing.T) {
	got, ok := reverseIPv4Name("192.168.1.25")
	if !ok {
		t.Fatal("reverseIPv4Name returned false")
	}
	if want := "25.1.168.192.in-addr.arpa"; got != want {
		t.Fatalf("reverse = %q, want %q", got, want)
	}
}
