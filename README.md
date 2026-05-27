# wifiscope

Cross-platform LAN device discovery for Linux, macOS, and Windows.

## Usage

```bash
go run .                  # scan the primary LAN
go run . --all            # scan all active local-use IPv4 interfaces
go run . --iface en0      # scan one interface
go run . --cidr 10.0.0.0/24
```

Useful tuning flags:

```bash
go run . --timeout 1s --workers 256 --ports 22,80,139,443,445,3389
```

The scanner combines ICMP, TCP connection/refusal probes, neighbor-table
entries, reverse DNS, mDNS, LLMNR, and NetBIOS. If a device is found but no
name can be resolved, it is printed as `unknown`.
