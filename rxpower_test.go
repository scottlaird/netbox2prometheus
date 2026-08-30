package main

import (
	"strings"
	"testing"

	netbox "github.com/netbox-community/go-netbox/v4"
	"go.yaml.in/yaml/v4"
)

func testIfaceOnDevice(id, deviceID int32, device, name string) netbox.Interface {
	iface := testInterface(id, device, name, nil)
	iface.Device.Id = deviceID
	return iface
}

func TestRxPowerMonitoredRule(t *testing.T) {
	platforms := map[int32]string{10: "eos", 11: "junos", 12: "linux", 13: "ios"}
	interfaces := []netbox.Interface{
		testIfaceOnDevice(1, 10, "sw1", "Ethernet2"),
		testIfaceOnDevice(2, 10, "sw1", "Ethernet1"), // same device, sorted
		testIfaceOnDevice(3, 11, "ex1", "xe-0/0/1"),
		testIfaceOnDevice(4, 12, "srv1", "eth0"),
		testIfaceOnDevice(5, 13, "rtr1", "Gi0/1"), // unknown platform, dropped
	}

	rule := rxPowerMonitoredRule(interfaces, platforms, "monitoring-if-rxpower", "example.com")
	if rule == nil {
		t.Fatal("got nil rule, want one")
	}
	if got, want := rule.Record, "interface:rx_power_dbm:monitored"; got != want {
		t.Errorf("record: got %q, want %q", got, want)
	}

	for _, w := range []string{
		`instance="ex1.example.com",ifName=~"xe-0/0/1"`,
		`instance="srv1.example.com",ifName=~"eth0"`,
		`instance="sw1.example.com",ifName=~"Ethernet1|Ethernet2"`,
	} {
		if !strings.Contains(rule.Expr, w) {
			t.Errorf("expr missing %q:\n%s", w, rule.Expr)
		}
	}
	if strings.Contains(rule.Expr, "rtr1") {
		t.Errorf("expr should not include the unknown-platform device:\n%s", rule.Expr)
	}
	if got, want := strings.Count(rule.Expr, "\nor "), 2; got != want {
		t.Errorf("got %d joins, want %d:\n%s", got, want, rule.Expr)
	}
}

// TestRxPowerMonitoredRuleEscapesRegex covers interface names containing regex
// metacharacters, which would otherwise match more than intended.
func TestRxPowerMonitoredRuleEscapesRegex(t *testing.T) {
	rule := rxPowerMonitoredRule(
		[]netbox.Interface{testIfaceOnDevice(1, 10, "sw1", "Ethernet1.100")},
		map[int32]string{10: "eos"}, "monitoring-if-rxpower", "example.com")
	if rule == nil {
		t.Fatal("got nil rule, want one")
	}
	if want := `ifName=~"Ethernet1\\.100"`; !strings.Contains(rule.Expr, want) {
		t.Errorf("expr missing %q:\n%s", want, rule.Expr)
	}
}

func TestRxPowerMonitoredRuleEmpty(t *testing.T) {
	if rule := rxPowerMonitoredRule(nil, nil, "monitoring-if-rxpower", "example.com"); rule != nil {
		t.Errorf("got %+v, want nil for no tagged interfaces", rule)
	}
}

func TestRxPowerRulesYAML(t *testing.T) {
	rules := rxPowerRecordRules()
	monitored := rxPowerMonitoredRule(
		[]netbox.Interface{
			testIfaceOnDevice(1, 10, "sw1", "Ethernet1"),
			testIfaceOnDevice(2, 11, "ex1", "xe-0/0/1"),
		},
		map[int32]string{10: "eos", 11: "junos"}, "monitoring-if-rxpower", "example.com")
	rules = append(rules, *monitored, rxPowerAlertRule())

	data, err := yaml.Marshal(&PromRuleGroups{Groups: []PromRuleGroup{
		{Name: "netbox_interface_rx_power", Rules: rules},
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("\n%s", data)
}
