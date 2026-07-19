package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"strings"
	"unicode"

	netbox "github.com/netbox-community/go-netbox/v4"
	"go.yaml.in/yaml/v4"
)

var (
	config = flag.String("config", "", "Path of a config file, with a .yaml, .json, or .cue extension")
)

type NEPingTarget struct {
	Name string `yaml:"name"`
	Host string `yaml:"host"`
	Type string `yaml:"type"`
}

type NEConf struct {
	Refresh    string `yaml:"refresh"`
	Nameserver string `yaml:"nameserver"`
}

type NEICMP struct {
	Interval string `yaml:"interval"`
	Timeout  string `yaml:"timeout"`
	Count    int    `yaml:"count"`
}

type NEConfig struct {
	Config  NEConf         `yaml:"conf"`
	Icmp    NEICMP         `yaml:"icmp"`
	Targets []NEPingTarget `yaml:"targets"`
}

type PEConfig struct {
	DNS     NEConf   `yaml:"dns"` // Identical between ping_exporter and network_exporter
	Ping    PEPing   `yaml:"ping"`
	Targets []string `yaml:"targets"`
}

type PEPing struct {
	Interval    string `yaml:"interval"`
	Timeout     string `yaml:"timeout"`
	HistorySize int    `yaml:"historysize"`
	PayloadSize int    `yaml:"payloadsize"`
}

func main() {
	flag.Parse()

	// Load config file
	var err error
	file := *config
	if file == "" {
		file, err = FindConfig("netbox2prometheus")
		if err != nil {
			log.Fatal(err)
		}
	}
	cfg, err := ParseConfig(file)
	if err != nil {
		log.Fatalf("Failed to parse config: %v", err)
	}

	c := netbox.NewAPIClientFor(cfg.Netbox.Host, cfg.Netbox.Token)
	ctx := context.Background()

	targets := []NEPingTarget{}

	// Fetch address, range, and prefix data from Netbox
	devices, _, err := c.DcimAPI.DcimDevicesList(ctx).
		Tag([]string{cfg.PingTagSlug}).
		Limit(9999).
		Execute()
	if err != nil {
		panic(err)
	}

	for _, device := range devices.GetResults() {
		name := hostname(*device.Name.Get(), cfg.DomainName)
		targets = append(targets, NEPingTarget{
			Name: name,
			Host: name,
			Type: "ICMP",
		})
	}

	ips, _, err := c.IpamAPI.IpamIpAddressesList(ctx).
		Tag([]string{cfg.PingTagSlug}).
		Limit(9999).
		Execute()
	if err != nil {
		panic(err)
	}
	for _, ip := range ips.GetResults() {
		name := hostname(ip.Address, cfg.DomainName) // Mostly just truncate the CIDR string
		targets = append(targets, NEPingTarget{
			Name: name,
			Host: name,
			Type: "ICMP",
		})
	}

	neconfig := NEConfig{
		Config: NEConf{
			Refresh:    cfg.DNSRefresh,
			Nameserver: cfg.DNSServer,
		},
		Icmp: NEICMP{
			Interval: cfg.ICMPInterval,
			Timeout:  cfg.ICMPTimeout,
			Count:    cfg.ICMPCount,
		},
		Targets: targets,
	}

	petargets := []string{}
	for _, t := range targets {
		petargets = append(petargets, t.Name)
	}

	peconfig := PEConfig{
		DNS: neconfig.Config,
		Ping: PEPing{
			Interval:    cfg.ICMPInterval,
			Timeout:     cfg.ICMPTimeout,
			HistorySize: 42,
			PayloadSize: 120,
		},
		Targets: petargets,
	}

	ne, err := yaml.Marshal(&neconfig)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(ne))

	pe, err := yaml.Marshal(&peconfig)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(pe))
}

func hostname(name string, domain string) string {
	if unicode.IsNumber(rune(name[0])) {
		split := strings.Split(name, "/")
		return split[0] // probably an IP address, truncate '/' but otherwise leave alone.
	}
	if strings.Contains(name, ".") {
		return name // already a FQDN
	}
	return name + "." + domain // Append the domain name
}
