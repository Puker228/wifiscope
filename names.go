package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

func lookupReverseDNSName(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return cleanDeviceName(names[0])
}

func lookupPTRMulticastName(ip string, multicastIP net.IP, port int, queryClass uint16, timeout time.Duration) (string, bool) {
	reverseName, ok := reverseIPv4Name(ip)
	if !ok {
		return "", false
	}

	conn, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return "", false
	}
	defer conn.Close()

	query := buildDNSQuery(reverseName, 12, queryClass)
	addr := &net.UDPAddr{IP: multicastIP, Port: port}
	if _, err := conn.WriteTo(query, addr); err != nil {
		return "", false
	}

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return "", false
		}
		if name := parseDNSPTRResponse(buf[:n], reverseName); name != "" {
			return name, true
		}
	}
}

func lookupNetBIOSName(ip string, timeout time.Duration) (string, bool) {
	targetIP := net.ParseIP(ip).To4()
	if targetIP == nil {
		return "", false
	}

	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: targetIP, Port: 137})
	if err != nil {
		return "", false
	}
	defer conn.Close()

	query := buildNetBIOSNodeStatusQuery()
	if _, err := conn.Write(query); err != nil {
		return "", false
	}

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return "", false
	}

	return parseNetBIOSNodeStatusResponse(buf[:n]), true
}

func reverseIPv4Name(ip string) (string, bool) {
	parsed := net.ParseIP(ip).To4()
	if parsed == nil {
		return "", false
	}

	return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", parsed[3], parsed[2], parsed[1], parsed[0]), true
}

func buildDNSQuery(name string, queryType uint16, queryClass uint16) []byte {
	msg := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(msg[4:6], 1)

	msg = append(msg, encodeDNSName(name)...)
	msg = binary.BigEndian.AppendUint16(msg, queryType)
	msg = binary.BigEndian.AppendUint16(msg, queryClass)

	return msg
}

func encodeDNSName(name string) []byte {
	var out []byte
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0)
	return out
}

func parseDNSPTRResponse(msg []byte, wantedName string) string {
	if len(msg) < 12 {
		return ""
	}

	questionCount := int(binary.BigEndian.Uint16(msg[4:6]))
	answerCount := int(binary.BigEndian.Uint16(msg[6:8]))
	authorityCount := int(binary.BigEndian.Uint16(msg[8:10]))
	additionalCount := int(binary.BigEndian.Uint16(msg[10:12]))

	offset := 12
	for i := 0; i < questionCount; i++ {
		_, next, ok := parseDNSName(msg, offset)
		if !ok || next+4 > len(msg) {
			return ""
		}
		offset = next + 4
	}

	recordCount := answerCount + authorityCount + additionalCount
	for i := 0; i < recordCount; i++ {
		name, next, ok := parseDNSName(msg, offset)
		if !ok || next+10 > len(msg) {
			return ""
		}
		offset = next

		recordType := binary.BigEndian.Uint16(msg[offset : offset+2])
		recordLength := int(binary.BigEndian.Uint16(msg[offset+8 : offset+10]))
		recordStart := offset + 10
		recordEnd := recordStart + recordLength
		if recordEnd > len(msg) {
			return ""
		}

		if recordType == 12 && sameDNSName(name, wantedName) {
			ptrName, _, ok := parseDNSName(msg, recordStart)
			if ok {
				return cleanDeviceName(ptrName)
			}
		}

		offset = recordEnd
	}

	return ""
}

func parseDNSName(msg []byte, offset int) (string, int, bool) {
	var labels []string
	next := offset
	jumped := false

	for jumps := 0; jumps < 16; jumps++ {
		if offset >= len(msg) {
			return "", 0, false
		}

		length := int(msg[offset])
		if length == 0 {
			if !jumped {
				next = offset + 1
			}
			return strings.Join(labels, "."), next, true
		}

		if length&0xC0 == 0xC0 {
			if offset+1 >= len(msg) {
				return "", 0, false
			}
			pointer := int(binary.BigEndian.Uint16(msg[offset:offset+2]) & 0x3FFF)
			if !jumped {
				next = offset + 2
			}
			offset = pointer
			jumped = true
			continue
		}

		offset++
		if offset+length > len(msg) {
			return "", 0, false
		}
		labels = append(labels, string(msg[offset:offset+length]))
		offset += length
	}

	return "", 0, false
}

func sameDNSName(a string, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

func buildNetBIOSNodeStatusQuery() []byte {
	msg := make([]byte, 12, 50)
	binary.BigEndian.PutUint16(msg[0:2], uint16(time.Now().UnixNano()))
	binary.BigEndian.PutUint16(msg[4:6], 1)

	msg = append(msg, encodeNetBIOSName("*")...)
	msg = binary.BigEndian.AppendUint16(msg, 0x0021)
	msg = binary.BigEndian.AppendUint16(msg, 0x0001)

	return msg
}

func encodeNetBIOSName(name string) []byte {
	padded := make([]byte, 16)
	for i := range padded {
		padded[i] = ' '
	}
	copy(padded, []byte(name))

	encoded := make([]byte, 1, 34)
	encoded[0] = 32
	for _, char := range padded {
		encoded = append(encoded, 'A'+((char>>4)&0x0F), 'A'+(char&0x0F))
	}
	encoded = append(encoded, 0)

	return encoded
}

func parseNetBIOSNodeStatusResponse(msg []byte) string {
	if len(msg) < 57 {
		return ""
	}

	offset := 12
	for i := 0; i < int(binary.BigEndian.Uint16(msg[4:6])); i++ {
		_, next, ok := parseDNSName(msg, offset)
		if !ok || next+4 > len(msg) {
			return ""
		}
		offset = next + 4
	}

	answerCount := int(binary.BigEndian.Uint16(msg[6:8]))
	for i := 0; i < answerCount; i++ {
		_, next, ok := parseDNSName(msg, offset)
		if !ok || next+10 > len(msg) {
			return ""
		}
		offset = next

		recordType := binary.BigEndian.Uint16(msg[offset : offset+2])
		recordLength := int(binary.BigEndian.Uint16(msg[offset+8 : offset+10]))
		recordStart := offset + 10
		recordEnd := recordStart + recordLength
		if recordEnd > len(msg) {
			return ""
		}

		if recordType == 0x0021 && recordLength > 1 {
			nameCount := int(msg[recordStart])
			entryStart := recordStart + 1
			for j := 0; j < nameCount; j++ {
				entryOffset := entryStart + j*18
				if entryOffset+18 > recordEnd {
					return ""
				}

				suffix := msg[entryOffset+15]
				flags := binary.BigEndian.Uint16(msg[entryOffset+16 : entryOffset+18])
				isGroupName := flags&0x8000 != 0
				if suffix == 0x00 && !isGroupName {
					return cleanDeviceName(string(msg[entryOffset : entryOffset+15]))
				}
			}
		}

		offset = recordEnd
	}

	return ""
}

func cleanDeviceName(name string) string {
	return strings.TrimSpace(strings.TrimSuffix(name, "."))
}
