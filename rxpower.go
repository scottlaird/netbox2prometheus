package main

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	log "github.com/golang/glog"
	netbox "github.com/netbox-community/go-netbox/v4"
	"go.yaml.in/yaml/v4"
)

// Recorded metric names. The first is the vendor-neutral union; the second is
// that union narrowed to the interfaces Netbox says to alert on.
const (
	rxPowerMetric          = "interface:rx_power_dbm"
	rxPowerMonitoredMetric = "interface:rx_power_dbm:monitored"

	// rxPowerFloor is the receive level, in dBm, below which an interface is
	// considered to be in trouble.
	rxPowerFloor = -15

	// rxPowerFor is deliberately long. A dirty or failing optic degrades over
	// days, and a short window would only catch link flaps that the
	// InterfaceDown alert already covers.
	rxPowerFor = "8h"
)

// rxPowerSource is one vendor's receive-power metric, as an expression that
// yields dBm.
type rxPowerSource struct {
	// Platform is the Netbox platform this source covers. Matching is on the
	// platform slug, lowercased.
	Platform string
	// Expr yields receive power in dBm, before label normalisation.
	Expr string
}

// rxPowerSources maps Netbox platforms to the metric that carries their
// receive power, already in dBm.
//
// Each expression is normalised to {instance, ifName} by rxPowerRecordRules,
// so nothing downstream has to know which vendor a series came from. That is
// what makes the alert and the filtered metric vendor-neutral: they are
// written once against the union, not once per platform.
var rxPowerSources = []rxPowerSource{
	{
		// snmp_exporter's shipped juniper_optics module already applies
		// scale: .01 to jnxDomCurrentRxLaserPower, so this is dBm, and its
		// lookups turn ifIndex into ifName.
		Platform: "junos",
		Expr:     "jnxDomCurrentRxLaserPower",
	},
	{
		// Arista reports DOM sensors through entPhySensorTable, whose entries
		// are named "DOM RX Power Sensor for Ethernet3/29/1" rather than being
		// keyed by ifIndex. This assumes the collector already resolves that
		// to an ifName label and yields dBm.
		Platform: "eos",
		Expr:     "arista_dom_rx_power_dbm",
	},
	{
		// wobcom/transceiver-exporter. Confirm the interface label name and
		// whether your build emits dBm: the published README documents only
		// transceiver_exporter_laser_rx_power_milliwatts and says to convert
		// with 10*log10() yourself. If yours emits milliwatts, use:
		//   10 * log10(transceiver_exporter_laser_rx_power_milliwatts)
		Platform: "linux",
		Expr:     `label_replace(transceiver_exporter_laser_rx_power_dbm, "ifName", "$1", "interface", "(.*)")`,
	},
}

// collectRxPowerRules writes recording and alerting rules for transceiver
// receive power.
//
// The rules are emitted as a single group because they chain: the union feeds
// the filtered metric, which feeds the alert. Prometheus evaluates rules
// within a group in order, and groups in parallel, so the chain only holds if
// they stay together and in this order.
func collectRxPowerRules(ctx context.Context, cfg *Config, client *netbox.APIClient, slug, filename string) error {
	interfaces, err := taggedInterfaces(ctx, client, slug)
	if err != nil {
		return err
	}
	platforms, err := devicePlatforms(ctx, client)
	if err != nil {
		return err
	}

	rules := rxPowerRecordRules()
	if monitored := rxPowerMonitoredRule(interfaces, platforms, slug, cfg.DomainName); monitored != nil {
		rules = append(rules, *monitored, rxPowerAlertRule())
	}

	groups := PromRuleGroups{Groups: []PromRuleGroup{{
		Name:  "netbox_interface_rx_power",
		Rules: rules,
	}}}

	data, err := yaml.Marshal(&groups)
	if err != nil {
		return fmt.Errorf("unable to marshal yaml: %v", err)
	}
	return writeFile(cfg, filename, data)
}

// rxPowerRecordRules builds the vendor-neutral union, one rule per source.
// Several rules recording the same name is how Prometheus expresses a union;
// the series stay distinct because their instances do.
//
// Each is reduced to {instance, ifName} with min(), which for a single-lane
// optic just drops the vendor's extra labels. For a multi-lane optic that
// reports per-lane series it keeps the worst lane, which is the one a
// low-power alert should be watching.
func rxPowerRecordRules() []PromRule {
	rules := []PromRule{}
	for _, source := range rxPowerSources {
		rules = append(rules, PromRule{
			Record: rxPowerMetric,
			Expr:   fmt.Sprintf("min by (instance, ifName) (%s)", source.Expr),
		})
	}
	return rules
}

// rxPowerMonitoredRule narrows the union to the interfaces tagged in Netbox,
// grouped one selector per device. It returns nil when nothing is tagged,
// since an empty expression is not valid PromQL.
func rxPowerMonitoredRule(interfaces []netbox.Interface, platforms map[int32]string, slug, domain string) *PromRule {
	byDevice := map[string][]string{}
	for _, iface := range interfaces {
		device, ok := interfaceDevice(iface, slug)
		if !ok {
			continue
		}
		if !knownPlatform(platforms[iface.Device.Id]) {
			// Nothing publishes receive power for this platform, so the
			// interface would silently never appear in the union.
			log.Warningf("Interface %q on %q is tagged %q but its platform %q has no receive power source; skipping.",
				iface.Name, device, slug, platforms[iface.Device.Id])
			continue
		}
		instance := hostname(device, domain)
		byDevice[instance] = append(byDevice[instance], iface.Name)
	}
	if len(byDevice) == 0 {
		return nil
	}

	instances := make([]string, 0, len(byDevice))
	for instance := range byDevice {
		instances = append(instances, instance)
	}
	sort.Strings(instances)

	selectors := make([]string, 0, len(instances))
	for _, instance := range instances {
		names := byDevice[instance]
		sort.Strings(names)
		quoted := make([]string, 0, len(names))
		for _, name := range names {
			quoted = append(quoted, regexp.QuoteMeta(name))
		}
		selectors = append(selectors, fmt.Sprintf("%s{instance=%q,ifName=~%q}",
			rxPowerMetric, instance, strings.Join(quoted, "|")))
	}

	return &PromRule{
		Record: rxPowerMonitoredMetric,
		Expr:   strings.Join(selectors, "\nor "),
	}
}

// rxPowerAlertRule is a single alert over the filtered metric. The Netbox
// tags decide which interfaces reach it, so there is no need for one rule per
// interface.
func rxPowerAlertRule() PromRule {
	return PromRule{
		Alert: "InterfaceRxPowerLow",
		Expr:  fmt.Sprintf("%s < %d", rxPowerMonitoredMetric, rxPowerFloor),
		For:   rxPowerFor,
		Labels: map[string]string{
			"severity": alertSeverity,
		},
		Annotations: map[string]string{
			"summary":     "Receive power on {{ $labels.ifName }} at {{ $labels.instance }} is low",
			"description": fmt.Sprintf("{{ $labels.ifName }} at {{ $labels.instance }} has been receiving {{ $value | printf \"%%.1f\" }} dBm, below %d dBm, for %s.", rxPowerFloor, rxPowerFor),
		},
	}
}

func knownPlatform(platform string) bool {
	for _, source := range rxPowerSources {
		if source.Platform == platform {
			return true
		}
	}
	return false
}

// devicePlatforms maps Netbox device ids to their platform slug, lowercased.
// Interfaces carry only a BriefDevice, which has no platform, so the devices
// have to be fetched separately.
func devicePlatforms(ctx context.Context, client *netbox.APIClient) (map[int32]string, error) {
	devices, _, err := client.DcimAPI.DcimDevicesList(ctx).Limit(9999).Execute()
	if err != nil {
		return nil, fmt.Errorf("unable to fetch devices: %v", err)
	}
	platforms := map[int32]string{}
	for _, device := range devices.GetResults() {
		if p := device.Platform.Get(); p != nil {
			platforms[device.Id] = strings.ToLower(p.Slug)
		}
	}
	return platforms, nil
}
