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

	rule := rxPowerMonitoredRule(rxPowerTargets(interfaces, platforms, "monitoring-if-rxpower", "example.com"))
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
	rule := rxPowerMonitoredRule(rxPowerTargets([]netbox.Interface{testIfaceOnDevice(1, 10, "sw1", "Ethernet1.100")}, map[int32]string{10: "eos"}, "monitoring-if-rxpower", "example.com"))
	if rule == nil {
		t.Fatal("got nil rule, want one")
	}
	if want := `ifName=~"Ethernet1\\.100"`; !strings.Contains(rule.Expr, want) {
		t.Errorf("expr missing %q:\n%s", want, rule.Expr)
	}
}

func TestRxPowerMonitoredRuleEmpty(t *testing.T) {
	if rule := rxPowerMonitoredRule(rxPowerTargets(nil, nil, "monitoring-if-rxpower", "example.com")); rule != nil {
		t.Errorf("got %+v, want nil for no tagged interfaces", rule)
	}
}

func TestRxPowerRulesYAML(t *testing.T) {
	rules := []PromRule{rxPowerRecordRules("example.com")}
	monitored := rxPowerMonitoredRule(rxPowerTargets([]netbox.Interface{
		testIfaceOnDevice(1, 10, "sw1", "Ethernet1"),
		testIfaceOnDevice(2, 11, "ex1", "xe-0/0/1"),
	}, map[int32]string{10: "eos", 11: "junos"}, "monitoring-if-rxpower", "example.com"))
	rules = append(rules, *monitored, rxPowerAlertRule())

	data, err := yaml.Marshal(&PromRuleGroups{Groups: []PromRuleGroup{
		{Name: "netbox_interface_rx_power", Rules: rules},
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("\n%s", data)
}

// TestRxPowerSourcesEOS pins the Arista conversion, which is easy to get wrong:
// EOS reports milliwatts scaled by 10^4, not dBm, and carries the interface
// name only inside entPhysicalDescr.
// TestRxPowerRecordRuleFilters covers the two exclusions, which are easy to
// drop by accident and fail quietly: an administratively shut port reads at the
// DOM floor, and Junos reports 0 for a port with no transceiver.
func TestRxPowerRecordRuleFilters(t *testing.T) {
	expr := rxPowerRecordRules("example.com").Expr
	for _, want := range []string{
		"unless on (instance, ifName) (ifAdminStatus == 2)",
		"jnxDomCurrentRxLaserPower != 0",
	} {
		if !strings.Contains(expr, want) {
			t.Errorf("union expr missing %q:\n%s", want, expr)
		}
	}
	// unless, not a join on ifAdminStatus == 1: a source without ifAdminStatus
	// at all must survive.
	if strings.Contains(expr, "ifAdminStatus == 1") {
		t.Errorf("union joins on admin-up, which would drop sources lacking ifAdminStatus:\n%s", expr)
	}
}

func TestRxPowerSourcesEOS(t *testing.T) {
	var expr string
	for _, source := range rxPowerSources {
		if source.Platform == "eos" {
			expr = source.Expr
		}
	}
	if expr == "" {
		t.Fatal("no eos source found")
	}
	for _, want := range []string{
		"10 * log10(",                        // milliwatts to dBm
		"/ 10000)",                           // entPhySensorPrecision 4
		`"ifName", "$1", "entPhysicalDescr"`, // descr carries the interface
		`DOM RX Power Sensor for (.*)`,       // and only receive power
		"} > 0)",                             // unlit optics excluded
	} {
		if !strings.Contains(expr, want) {
			t.Errorf("eos expr missing %q:\n%s", want, expr)
		}
	}
	if strings.Contains(expr, "entPhysicalName") {
		t.Errorf("eos expr uses entPhysicalName, which is empty on EOS:\n%s", expr)
	}
}

func TestRxPowerMissingRules(t *testing.T) {
	targets := rxPowerTargets([]netbox.Interface{
		testIfaceOnDevice(1, 10, "sw1", "Ethernet2"),
		testIfaceOnDevice(2, 10, "sw1", "Ethernet1"),
		testIfaceOnDevice(3, 13, "rtr1", "Gi0/1"), // unknown platform, dropped
	}, map[int32]string{10: "eos", 13: "ios"}, "monitoring-if-rxpower", "example.com")

	rules := rxPowerMissingRules(targets)
	if got, want := len(rules), 2; got != want {
		t.Fatalf("got %d rules, want %d", got, want)
	}
	// Sorted, so Ethernet1 comes first.
	if got, want := rules[0].Expr,
		`absent(interface:rx_power_dbm:monitored{instance="sw1.example.com",ifName="Ethernet1"})`; got != want {
		t.Errorf("expr: got %q, want %q", got, want)
	}
	if got, want := rules[0].Alert, "InterfaceRxPowerMissing"; got != want {
		t.Errorf("alert: got %q, want %q", got, want)
	}
	// An equality matcher, not a regex: absent() only carries labels through
	// for equality matchers, so the alert would otherwise lose instance/ifName.
	for _, r := range rules {
		if strings.Contains(r.Expr, "=~") {
			t.Errorf("expr uses a regex matcher, which absent() cannot carry labels through:\n%s", r.Expr)
		}
	}
}

func typedIface(id, deviceID int32, device, name, typ string) netbox.Interface {
	i := testIfaceOnDevice(id, deviceID, device, name)
	v := netbox.InterfaceTypeValue(typ)
	i.Type = netbox.InterfaceType{Value: &v}
	return i
}

func TestMultiLane(t *testing.T) {
	tests := []struct {
		typ  string
		want bool
	}{
		{"40gbase-x-qsfpp", true},
		{"100gbase-x-qsfp28", true},
		{"400gbase-x-qsfpdd", true},
		{"10gbase-x-sfpp", false},
		{"25gbase-x-sfp28", false}, // sfp28, not qsfp28
		{"1000base-t", false},
	}
	for _, tt := range tests {
		if got := multiLane(typedIface(1, 10, "sw1", "Ethernet1", tt.typ)); got != tt.want {
			t.Errorf("multiLane(%s): got %v, want %v", tt.typ, got, tt.want)
		}
	}
}

// TestRxPowerMonitoredRuleLanes covers a QSFP reading as the worst of its
// lanes, while a broken-out cage keeps one series per lane.
func TestRxPowerMonitoredRuleLanes(t *testing.T) {
	targets := rxPowerTargets([]netbox.Interface{
		typedIface(1, 10, "sw1", "Ethernet11/1", "40gbase-x-qsfpp"), // whole cage
		typedIface(2, 10, "sw1", "Ethernet31", "40gbase-x-qsfpp"),   // cage, no lane suffix
		typedIface(3, 10, "sw1", "Ethernet25/2", "10gbase-x-sfpp"),  // broken out
	}, map[int32]string{10: "eos"}, "monitoring-if-rxpower", "example.com")

	rule := rxPowerMonitoredRule(targets)
	if rule == nil {
		t.Fatal("got nil rule, want one")
	}
	for _, want := range []string{
		// Single-lane keeps an exact match.
		`ifName=~"Ethernet25/2"`,
		// A cage aggregates its lanes and is relabelled to the Netbox name.
		`label_replace(min by (instance) (interface:rx_power_dbm{instance="sw1.example.com",ifName=~"Ethernet11/[0-9]+"}), "ifName", "Ethernet11/1", "instance", ".*")`,
		// Netbox holds this one without a lane suffix; the lanes are still there.
		`ifName=~"Ethernet31/[0-9]+"`,
	} {
		if !strings.Contains(rule.Expr, want) {
			t.Errorf("expr missing %q:\n%s", want, rule.Expr)
		}
	}
	// Relabelling before the aggregation would give the lanes one label set,
	// which is not a legal vector, and Prometheus rejects the whole expression.
	if strings.Contains(rule.Expr, `min by (instance, ifName) (label_replace`) {
		t.Errorf("expr relabels before aggregating:\n%s", rule.Expr)
	}
}

// TestRxPowerSourcesLinux pins the two things that make the Linux source
// different from the SNMP ones: transceiver-exporter already publishes dBm, so
// applying a log10 to it would be wrong, and it is scraped on the host, so its
// instance label is "host:port" rather than the FQDN the rest of the union
// keys on.
func TestRxPowerSourcesLinux(t *testing.T) {
	var source rxPowerSource
	for _, s := range rxPowerSources {
		if s.Platform == "linux" {
			source = s
		}
	}
	if source.Platform == "" {
		t.Fatal("no linux source found")
	}
	if !strings.Contains(source.Expr, "transceiver_laser_rx_power_dbm") {
		t.Errorf("linux source does not read transceiver_laser_rx_power_dbm:\n%s", source.Expr)
	}
	if strings.Contains(source.Expr, "log10") {
		t.Errorf("linux source applies log10, but the exporter already emits dBm:\n%s", source.Expr)
	}
	if !source.InstanceHasPort {
		t.Error("linux source is scraped on the host, so InstanceHasPort must be set")
	}
}

// The instance rewrite has to produce the same FQDN that rxPowerTargets builds
// with hostname(), or the union and the filtered metric key on different
// strings and the Linux series silently never match.
func TestRxPowerRecordRuleNormalisesExporterInstance(t *testing.T) {
	expr := rxPowerRecordRules("example.com").Expr
	want := `"instance", "${1}.example.com", "instance", "([^:]+):[0-9]+"`
	if !strings.Contains(expr, want) {
		t.Errorf("union does not rewrite the exporter instance to an FQDN;\nwant substring: %s\ngot:\n%s", want, expr)
	}
	// The SNMP sources already carry an FQDN and must not be rewritten.
	if strings.Count(expr, "([^:]+):[0-9]+") != 1 {
		t.Errorf("instance rewrite applied to more than the exporter source:\n%s", expr)
	}
}
