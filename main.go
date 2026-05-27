package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

const defaultPortList = "22,80,139,443,445,3389,5357,8000,8080,8443"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "wifiscope: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	var opts ScanOptions

	flags := flag.NewFlagSet("wifiscope", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)

	flags.StringVar(&opts.CIDR, "cidr", "", "scan an explicit IPv4 CIDR, for example 192.168.1.0/24")
	flags.StringVar(&opts.InterfaceName, "iface", "", "scan the IPv4 network assigned to one interface")
	flags.BoolVar(&opts.AllInterfaces, "all", false, "scan all active local-use IPv4 interfaces")
	flags.DurationVar(&opts.Timeout, "timeout", 700*time.Millisecond, "per-probe timeout")
	flags.IntVar(&opts.Workers, "workers", 128, "number of concurrent host workers")
	portsText := flags.String("ports", defaultPortList, "comma-separated TCP ports used as host-presence probes")

	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if opts.Workers < 1 {
		return fmt.Errorf("--workers must be greater than zero")
	}
	if opts.Timeout <= 0 {
		return fmt.Errorf("--timeout must be greater than zero")
	}

	ports, err := parsePorts(*portsText)
	if err != nil {
		return err
	}
	opts.Ports = ports

	targets, err := discoverNetworkTargets(opts)
	if err != nil {
		return err
	}

	fmt.Printf("Scanning %d network(s): %s\n", len(targets), formatTargets(targets))
	devices, err := scanNetworks(targets, opts)
	if err != nil {
		return err
	}

	for _, device := range devices {
		name := device.Name
		if name == "" {
			name = "unknown"
		}

		details := []string{"seen: " + strings.Join(device.SeenBy, ",")}
		if device.NameSource != "" {
			details = append(details, "name: "+device.NameSource)
		}
		fmt.Printf("Device found: %s (%s) [%s]\n", device.IP, name, strings.Join(details, ", "))
	}

	fmt.Printf("Scan completed: %d device(s) found\n", len(devices))
	return nil
}
