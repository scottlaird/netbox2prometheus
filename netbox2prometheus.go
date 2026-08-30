package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
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

type FileSDConfigs []FileSDConfig

type FileSDConfig struct {
	Targets []string          `yaml:"targets"`
	Labels  map[string]string `yaml:"labels,omitempty"`
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
			Nameserver: cfg.DNSServer + ":53",
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
		DNS: NEConf{
			Refresh:    cfg.DNSRefresh,
			Nameserver: cfg.DNSServer,
		},
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

	err = writeFile(cfg, "network_exporter.yml", ne)
	if err != nil {
		panic(err)
	}

	pe, err := yaml.Marshal(&peconfig)
	if err != nil {
		panic(err)
	}

	err = writeFile(cfg, "ping_exporter.yml", pe)
	if err != nil {
		panic(err)
	}

	labels := map[string]string{}
	err = collectTargets(ctx, cfg, c, labels, "monitoring-node", "9100", "targets_node.yml")
	if err != nil {
		panic(err)
	}
	err = collectTargets(ctx, cfg, c, labels, "monitoring-chrony", "9123", "targets_chrony.yml")
	if err != nil {
		panic(err)
	}
	err = collectTargets(ctx, cfg, c, labels, "monitoring-caddy", "2019", "targets_caddy.yml")
	if err != nil {
		panic(err)
	}
	err = collectTargets(ctx, cfg, c, labels, "monitoring-ts2phc", "8089", "targets_ts2phc.yml")
	if err != nil {
		panic(err)
	}
	err = collectTargets(ctx, cfg, c, labels, "monitoring-snmp-generic", "", "targets_snmp_generic.yml")
	if err != nil {
		panic(err)
	}
	err = collectTargets(ctx, cfg, c, labels, "monitoring-snmp-pdu", "", "targets_snmp_pdu.yml")
	if err != nil {
		panic(err)
	}
	err = collectTargets(ctx, cfg, c, labels, "monitoring-snmp-unifi", "", "targets_snmp_unifi.yml")
	if err != nil {
		panic(err)
	}
	err = collectTargets(ctx, cfg, c, labels, "monitoring-snmp-juniper", "", "targets_snmp_juniper.yml")
	if err != nil {
		panic(err)
	}
	err = collectTargets(ctx, cfg, c, labels, "monitoring-snmp-arista", "", "targets_snmp_arista.yml")
	if err != nil {
		panic(err)
	}
	err = collectTargets(ctx, cfg, c, labels, "monitoring-snmp-vyos", "", "targets_snmp_vyos.yml")
	if err != nil {
		panic(err)
	}

	err = collectTargets(ctx, cfg, c, labels, "monitoring-transceiver_exporter", "9458", "targets_transceiver.yml")
	if err != nil {
		panic(err)
	}

	err = collectInterfaceAlerts(ctx, cfg, c, "monitoring-if-up", "monitoring-if-speed", "alerts_interfaces.yml")
	if err != nil {
		panic(err)
	}

	err = collectRxPowerRules(ctx, cfg, c, "monitoring-if-rxpower", "rules_transceivers.yml")
	if err != nil {
		panic(err)
	}
}

func collectTargets(ctx context.Context, cfg *Config, client *netbox.APIClient, labels map[string]string, slug string, port string, filename string) error {
	fileConfig := FileSDConfig{
		Labels: labels,
	}

	// Fetch address, range, and prefix data from Netbox
	devices, _, err := client.DcimAPI.DcimDevicesList(ctx).
		Tag([]string{slug}).
		Limit(9999).
		Execute()
	if err != nil {
		return fmt.Errorf("unable to fetch targets: %v", err)
	}

	for _, device := range devices.GetResults() {
		target := *device.Name.Get()
		if port != "" {
			target = target + ":" + port
		}
		fileConfig.Targets = append(fileConfig.Targets, target)
	}

	fileConfigs := FileSDConfigs{fileConfig}

	data, err := yaml.Marshal(&fileConfigs)
	if err != nil {
		return fmt.Errorf("unable to marshal yaml: %v", err)
	}

	return writeFile(cfg, filename, data)
}

func writeFile(cfg *Config, filename string, data []byte) error {
	path := filepath.Join(cfg.OutputDirectory, filename)
	return os.WriteFile(path, data, 0644)
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
