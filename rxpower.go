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

	// rxPowerMissingFor is shorter than rxPowerFor. A reading that has stopped
	// arriving is a different fault from one that is drifting down, and it does
	// not need days to confirm; it is long enough to sit out a maintenance
	// window with an optic unplugged.
	rxPowerMissingFor = "1h"

	// ifAdminStatusDown is the ifAdminStatus value for an interface that has
	// been shut down. The others are up(1) and testing(3).
	ifAdminStatusDown = 2
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
		//
		// Junos reports exactly 0 for a port with no transceiver in it, which
		// as dBm reads as a healthy 1 mW rather than as missing. On an
		// EX4300-48MP that is all 48 copper ports. A real optic landing on
		// exactly 0.00 would be dropped too, but it reappears on the next
		// scrape.
		Platform: "junos",
		Expr:     "jnxDomCurrentRxLaserPower != 0",
	},
	{
		// Arista publishes DOM readings as ENTITY-SENSOR-MIB sensors keyed by
		// entPhysicalIndex, not by ifIndex. The interface appears only inside
		// entPhysicalDescr, which reads "DOM RX Power Sensor for Ethernet11/1";
		// entPhysicalName is empty on EOS, so the description is the only
		// source for it.
		//
		// The reading is milliwatts rather than dBm. EOS reports
		// entPhySensorType watts, entPhySensorScale milli and
		// entPhySensorPrecision 4, so the raw value is mW scaled by 10^4:
		// 8144 is 0.8144 mW, which is -0.89 dBm.
		//
		// Unlit optics report 0, which would convert to -Inf and trip the low
		// power alert, so they are filtered out. The > 0 belongs only here:
		// the other sources are already dBm, where zero and negative readings
		// are ordinary.
		Platform: "eos",
		Expr: `10 * log10(label_replace((entPhySensorValue{entPhysicalDescr=~"DOM RX Power Sensor for .*"} > 0),` +
			` "ifName", "$1", "entPhysicalDescr", "DOM RX Power Sensor for (.*)") / 10000)`,
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

	targets := rxPowerTargets(interfaces, platforms, slug, cfg.DomainName)
	rules := []PromRule{rxPowerRecordRules()}
	if monitored := rxPowerMonitoredRule(targets); monitored != nil {
		rules = append(rules, *monitored, rxPowerAlertRule())
		rules = append(rules, rxPowerMissingRules(targets)...)
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

// rxPowerRecordRules builds the vendor-neutral union as one rule.
//
// Several rules recording the same name would also union, since the series
// stay distinct by instance, but promtool cannot see that and rejects the file
// as duplicate rules. `or` says the same thing in a single rule: it takes
// everything on the left, plus the series on the right whose label sets are
// not already there. The sources cover different platforms and so different
// instances, which makes the union lossless.
//
// Should one instance ever appear in two sources, the earlier one silently
// wins. The order here is Junos, EOS, Linux.
//
// Each source is reduced to {instance, ifName} with min(), which for a
// single-lane optic just drops the vendor's extra labels. For a multi-lane
// optic that reports per-lane series it keeps the worst lane, which is the one
// a low-power alert should be watching.
//
// Administratively shut interfaces are then removed. A shut port reads at the
// DOM floor, -40 dBm on Arista, which is true but not worth graphing or
// alerting on: nobody expects light from a port they turned off. Operationally
// down is deliberately left in, since a port that is enabled and dark is
// exactly what the alert is for.
//
// It is `unless` rather than a join against ifAdminStatus == 1 so that a source
// with no ifAdminStatus at all is kept. The Linux exporter has none.
func rxPowerRecordRules() PromRule {
	exprs := make([]string, 0, len(rxPowerSources))
	for _, source := range rxPowerSources {
		exprs = append(exprs, fmt.Sprintf("min by (instance, ifName) (%s)", source.Expr))
	}
	return PromRule{
		Record: rxPowerMetric,
		Expr: fmt.Sprintf("(\n%s\n)\nunless on (instance, ifName) (ifAdminStatus == %d)",
			strings.Join(exprs, "\nor "), ifAdminStatusDown),
	}
}

// rxPowerTarget is one interface Netbox says to watch: the bare device name
// for labels and prose, and the FQDN the metrics are actually keyed by.
type rxPowerTarget struct {
	Device   string
	Instance string
	IfName   string
}

// rxPowerTargets selects the tagged interfaces that could have a reading,
// sorted so the generated rules are stable between runs.
func rxPowerTargets(interfaces []netbox.Interface, platforms map[int32]string, slug, domain string) []rxPowerTarget {
	targets := []rxPowerTarget{}
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
		targets = append(targets, rxPowerTarget{
			Device:   device,
			Instance: hostname(device, domain),
			IfName:   iface.Name,
		})
	}
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].Instance != targets[j].Instance {
			return targets[i].Instance < targets[j].Instance
		}
		return targets[i].IfName < targets[j].IfName
	})
	return targets
}

// rxPowerMonitoredRule narrows the union to the tagged interfaces, grouped one
// selector per device. It returns nil when nothing is tagged, since an empty
// expression is not valid PromQL.
func rxPowerMonitoredRule(targets []rxPowerTarget) *PromRule {
	byDevice := map[string][]string{}
	instances := []string{}
	for _, t := range targets {
		if _, seen := byDevice[t.Instance]; !seen {
			instances = append(instances, t.Instance)
		}
		byDevice[t.Instance] = append(byDevice[t.Instance], t.IfName)
	}
	if len(byDevice) == 0 {
		return nil
	}

	selectors := make([]string, 0, len(instances))
	for _, instance := range instances {
		names := byDevice[instance]
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

// rxPowerMissingRules builds one alert per tagged interface for a reading that
// is not arriving at all.
//
// This cannot be one rule over the filtered metric the way the low power alert
// is. A series that does not exist cannot be compared, so an interface that
// stops reporting simply leaves the metric and nothing fires: no data looks
// exactly like healthy. absent() answers "should this series be here", which
// only makes sense one interface at a time.
//
// It catches an optic being pulled, and also the case that prompted it: a
// tagged interface that never had a reading, because the transceiver is a DAC
// or does not implement DOM.
func rxPowerMissingRules(targets []rxPowerTarget) []PromRule {
	rules := make([]PromRule, 0, len(targets))
	for _, t := range targets {
		selector := fmt.Sprintf("%s{instance=%q,ifName=%q}", rxPowerMonitoredMetric, t.Instance, t.IfName)
		rules = append(rules, PromRule{
			Alert: "InterfaceRxPowerMissing",
			Expr:  fmt.Sprintf("absent(%s)", selector),
			For:   rxPowerMissingFor,
			Labels: map[string]string{
				"severity":  alertSeverity,
				"device":    t.Device,
				"interface": t.IfName,
			},
			Annotations: map[string]string{
				"summary": fmt.Sprintf("No receive power reading for %s on %s", t.IfName, t.Device),
				"description": fmt.Sprintf("%s on %s is tagged for receive power monitoring but is not reporting a level. "+
					"The optic may have been removed, the port shut, or the transceiver may not support digital optical monitoring.",
					t.IfName, t.Device),
			},
		})
	}
	return rules
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
