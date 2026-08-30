package main

import (
	"context"
	"fmt"
	"strconv"

	log "github.com/golang/glog"
	netbox "github.com/netbox-community/go-netbox/v4"
	"go.yaml.in/yaml/v4"
)

// PromRuleGroups is the root of a Prometheus rules file.
type PromRuleGroups struct {
	Groups []PromRuleGroup `yaml:"groups"`
}

// PromRuleGroup is one group of alerting rules. Rules within a group are
// evaluated sequentially, at a regular interval.
type PromRuleGroup struct {
	Name  string     `yaml:"name"`
	Rules []PromRule `yaml:"rules"`
}

// PromRule is a single alerting or recording rule. Exactly one of Alert and
// Record is set.
type PromRule struct {
	Alert       string            `yaml:"alert,omitempty"`
	Record      string            `yaml:"record,omitempty"`
	Expr        string            `yaml:"expr"`
	For         string            `yaml:"for,omitempty"`
	Labels      map[string]string `yaml:"labels,omitempty"`
	Annotations map[string]string `yaml:"annotations,omitempty"`
}

const (
	// ifOperStatus values. An interface that is neither up nor down is in one
	// of the states listed in ifOperStatusOther, which is rare enough to be
	// worth calling out separately.
	ifOperStatusUp    = 1
	ifOperStatusDown  = 2
	ifOperStatusOther = "3=testing, 4=unknown, 5=dormant, 6=notPresent, 7=lowerLayerDown"

	// A link that is down is worth knowing about quickly. A speed mismatch is
	// a config or negotiation problem rather than an outage, and does not
	// flap, so it waits longer.
	// mtuFor is long enough that a change being rolled out across a switch
	// does not alert while it is in progress.
	mtuFor = "30m"

	alertForUp    = "5m"
	alertForSpeed = "30m"
	alertSeverity = "warning"
)

// mtuOffsets maps a Netbox platform to the difference between what ifMtu
// reports and the MTU Netbox records, in bytes.
//
// EOS reports the payload MTU, the same number Netbox holds, so the offset is
// zero. That is measured, not assumed: across 30 tagged interfaces on swa, 24
// agreed exactly and the six that did not were real drift, ports sitting at
// Arista's 9214 default where Netbox asks for 9100 or 1500.
//
// Junos is deliberately absent. Its physical ports report a mix: ge-0/0/0 at
// 9014 and ge-0/0/10 at 1514, both payload plus the 14 byte header, but others
// at 9100 with no offset, because a Junos `mtu` statement is itself an L2
// figure. Which convention Netbox should hold for those is a decision about the
// data rather than something to infer, so Junos interfaces are skipped with a
// warning until one is picked. Adding a platform here is a one line change.
var mtuOffsets = map[string]int32{
	"eos": 0,
}

// interfaceMTURules builds one alert per interface whose configured MTU can be
// compared against the device.
//
// Interfaces are skipped, with a warning rather than silently, when Netbox has
// no MTU for them, when they are disabled in Netbox, or when their platform has
// no known relationship between ifMtu and the Netbox value.
func interfaceMTURules(interfaces []netbox.Interface, platforms map[int32]string, slug, domain string) []PromRule {
	rules := []PromRule{}
	for _, iface := range interfaces {
		device, ok := interfaceDevice(iface, slug)
		if !ok {
			continue
		}
		if iface.Enabled != nil && !*iface.Enabled {
			// Disabled ports are exempt from the MTU policy.
			continue
		}
		if !iface.Mtu.IsSet() || iface.Mtu.Get() == nil {
			log.Warningf("Interface %q on %q is tagged %q but has no MTU in Netbox; skipping the MTU check.",
				iface.Name, device, slug)
			continue
		}
		platform := platforms[iface.Device.Id]
		offset, known := mtuOffsets[platform]
		if !known {
			log.Warningf("Interface %q on %q is on platform %q, where the relationship between ifMtu and the Netbox MTU is not established; skipping the MTU check.",
				iface.Name, device, platform)
			continue
		}
		want := *iface.Mtu.Get() + offset

		rules = append(rules, PromRule{
			Alert: "InterfaceMTUMismatch",
			Expr:  fmt.Sprintf("%s != %d", metricSelector("ifMtu", hostname(device, domain), iface.Name), want),
			For:   mtuFor,
			Labels: map[string]string{
				"severity":  alertSeverity,
				"device":    device,
				"interface": iface.Name,
			},
			Annotations: map[string]string{
				"summary": fmt.Sprintf("MTU on %s on %s is not %d", iface.Name, device, want),
				"description": fmt.Sprintf("Netbox records %s on %s with an MTU of %d, but the device reports {{ $value }}.",
					iface.Name, device, *iface.Mtu.Get()),
			},
		})
	}
	return rules
}

// collectInterfaceAlerts writes a Prometheus alerting rules file covering
// every Netbox interface tagged for monitoring.
//
// Interfaces tagged upSlug get an alert that fires when ifOperStatus reports
// anything other than up. Interfaces tagged speedSlug get an alert that fires
// when ifHighSpeed disagrees with the speed recorded in Netbox. The two tags
// are independent: an interface may carry either, both or neither.
//
// The instance label is the device's FQDN, built with hostname() from
// cfg.DomainName, which is what the existing Prometheus scrape configs use.
// The device label keeps the bare Netbox name, which reads better in alerts.
func collectInterfaceAlerts(ctx context.Context, cfg *Config, client *netbox.APIClient, upSlug, speedSlug, filename string) error {
	upInterfaces, err := taggedInterfaces(ctx, client, upSlug)
	if err != nil {
		return err
	}
	speedInterfaces, err := taggedInterfaces(ctx, client, speedSlug)
	if err != nil {
		return err
	}
	platforms, err := devicePlatforms(ctx, client)
	if err != nil {
		return err
	}
	upRules := interfaceUpRules(upInterfaces, upSlug, cfg.DomainName)
	upRules = append(upRules, interfaceMTURules(upInterfaces, platforms, upSlug, cfg.DomainName)...)
	speedRules := interfaceSpeedRules(speedInterfaces, speedSlug, cfg.DomainName)

	groups := PromRuleGroups{}
	if len(upRules) > 0 {
		groups.Groups = append(groups.Groups, PromRuleGroup{
			Name:  "netbox_interface_up",
			Rules: upRules,
		})
	}
	if len(speedRules) > 0 {
		groups.Groups = append(groups.Groups, PromRuleGroup{
			Name:  "netbox_interface_speed",
			Rules: speedRules,
		})
	}

	data, err := yaml.Marshal(&groups)
	if err != nil {
		return fmt.Errorf("unable to marshal yaml: %v", err)
	}
	return writeFile(cfg, filename, data)
}

// interfaceUpRules builds two rules per interface: InterfaceDown for the
// ordinary case of ifOperStatus reporting down, and InterfaceUnusualState for
// anything else that is not up, which is rare and needs the raw enum value to
// be interpretable.
func interfaceUpRules(interfaces []netbox.Interface, slug, domain string) []PromRule {
	rules := []PromRule{}
	for _, iface := range interfaces {
		device, ok := interfaceDevice(iface, slug)
		if !ok {
			continue
		}
		selector := metricSelector("ifOperStatus", hostname(device, domain), iface.Name)
		labels := map[string]string{
			"severity":  alertSeverity,
			"device":    device,
			"interface": iface.Name,
		}

		rules = append(rules, PromRule{
			Alert:  "InterfaceDown",
			Expr:   fmt.Sprintf("%s == %d", selector, ifOperStatusDown),
			For:    alertForUp,
			Labels: labels,
			Annotations: map[string]string{
				"summary":     fmt.Sprintf("Interface %s on %s is down", iface.Name, device),
				"description": fmt.Sprintf("%s on %s is down.", iface.Name, device),
			},
		})

		rules = append(rules, PromRule{
			Alert:  "InterfaceUnusualState",
			Expr:   fmt.Sprintf("(%s != %d) != %d", selector, ifOperStatusUp, ifOperStatusDown),
			For:    alertForUp,
			Labels: labels,
			Annotations: map[string]string{
				"summary":     fmt.Sprintf("Interface %s on %s is not up, and not down either", iface.Name, device),
				"description": fmt.Sprintf("%s on %s is not up. Current state is {{ $value }} (%s).", iface.Name, device, ifOperStatusOther),
			},
		})
	}
	return rules
}

// interfaceSpeedRules builds one InterfaceSpeedMismatch rule per interface
// that records a usable speed in Netbox.
func interfaceSpeedRules(interfaces []netbox.Interface, slug, domain string) []PromRule {
	rules := []PromRule{}
	for _, iface := range interfaces {
		device, ok := interfaceDevice(iface, slug)
		if !ok {
			continue
		}
		if !iface.Speed.IsSet() || iface.Speed.Get() == nil {
			log.Warningf("Interface %q on %q is tagged %q but has no speed in Netbox; skipping.", iface.Name, device, slug)
			continue
		}
		// The speed field is read as Mbps, matching ifHighSpeed directly.
		// Netbox documents it as kbps, so this is a deliberate local
		// convention: a 10G interface holds 10000 here, not 10000000, and the
		// Netbox UI will render that as "10 Mbps".
		mbps := *iface.Speed.Get()

		rules = append(rules, PromRule{
			Alert: "InterfaceSpeedMismatch",
			Expr:  fmt.Sprintf("%s != %d", metricSelector("ifHighSpeed", hostname(device, domain), iface.Name), mbps),
			For:   alertForSpeed,
			Labels: map[string]string{
				"severity":  alertSeverity,
				"device":    device,
				"interface": iface.Name,
			},
			Annotations: map[string]string{
				"summary":     fmt.Sprintf("Interface %s on %s is not running at %d Mbps", iface.Name, device, mbps),
				"description": fmt.Sprintf("Netbox records %s on %s as %d Mbps, but ifHighSpeed reports {{ $value }} Mbps.", iface.Name, device, mbps),
			},
		})
	}
	return rules
}

// taggedInterfaces returns every Netbox interface carrying the given tag.
func taggedInterfaces(ctx context.Context, client *netbox.APIClient, slug string) ([]netbox.Interface, error) {
	interfaces, _, err := client.DcimAPI.DcimInterfacesList(ctx).
		Tag([]string{slug}).
		Limit(9999).
		Execute()
	if err != nil {
		return nil, fmt.Errorf("unable to fetch interfaces tagged %q: %v", slug, err)
	}
	return interfaces.GetResults(), nil
}

// interfaceDevice returns the name of the device an interface belongs to.
// Devices without a name cannot be scraped, so they are skipped.
func interfaceDevice(iface netbox.Interface, slug string) (string, bool) {
	name := iface.Device.Name.Get()
	if name == nil || *name == "" {
		log.Warningf("Interface %q (id %d) is tagged %q but its device has no name; skipping.", iface.Name, iface.Id, slug)
		return "", false
	}
	return *name, true
}

// metricSelector builds a PromQL instant vector selector for one interface.
func metricSelector(metric, device, ifName string) string {
	return fmt.Sprintf("%s{instance=%s,ifName=%s}", metric, strconv.Quote(device), strconv.Quote(ifName))
}
