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
	// kbpsPerMbps converts a Netbox interface speed into the units used by
	// ifHighSpeed. Netbox stores speed in kbps; ifHighSpeed is in Mbps, so a
	// 10G interface is 10000000 in Netbox and 10000 in ifHighSpeed.
	kbpsPerMbps = 1000

	// ifOperStatus values. An interface that is neither up nor down is in one
	// of the states listed in ifOperStatusOther, which is rare enough to be
	// worth calling out separately.
	ifOperStatusUp    = 1
	ifOperStatusDown  = 2
	ifOperStatusOther = "3=testing, 4=unknown, 5=dormant, 6=notPresent, 7=lowerLayerDown"

	// A link that is down is worth knowing about quickly. A speed mismatch is
	// a config or negotiation problem rather than an outage, and does not
	// flap, so it waits longer.
	alertForUp    = "5m"
	alertForSpeed = "30m"
	alertSeverity = "warning"
)

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
	upRules := interfaceUpRules(upInterfaces, upSlug, cfg.DomainName)
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
		kbps := *iface.Speed.Get()
		if kbps%kbpsPerMbps != 0 {
			// ifHighSpeed is a whole number of Mbps, so a speed that is not a
			// multiple of 1000 kbps can never compare equal. Alerting on it
			// would fire forever.
			log.Warningf("Interface %q on %q has speed %d kbps, which is not a whole number of Mbps; skipping.", iface.Name, device, kbps)
			continue
		}
		mbps := kbps / kbpsPerMbps

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
				"description": fmt.Sprintf("Netbox records %s on %s as %d kbps (%d Mbps), but ifHighSpeed reports {{ $value }} Mbps.", iface.Name, device, kbps, mbps),
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
