package main

import (
	"testing"
	"time"

	netbox "github.com/netbox-community/go-netbox/v4"
	"go.yaml.in/yaml/v4"
)

func testInterface(id int32, device, name string, speedKbps *int32) netbox.Interface {
	iface := netbox.Interface{Id: id, Name: name}
	if device != "" {
		iface.Device.Name = *netbox.NewNullableString(&device)
	}
	if speedKbps != nil {
		iface.Speed = *netbox.NewNullableInt32(speedKbps)
	}
	return iface
}

func ptr(i int32) *int32 { return &i }

func TestInterfaceUpRules(t *testing.T) {
	rules := interfaceUpRules([]netbox.Interface{
		testInterface(1, "sw1", "Ethernet1/1", nil),
		testInterface(2, "", "Ethernet1/2", nil), // no device name, skipped
	}, "monitoring-if-up", "example.com")

	// Two rules per interface: the ordinary down case, and everything else
	// that is not up.
	if got, want := len(rules), 2; got != want {
		t.Fatalf("got %d rules, want %d", got, want)
	}

	sel := `ifOperStatus{instance="sw1.example.com",ifName="Ethernet1/1"}`
	want := []struct{ alert, expr string }{
		{"InterfaceDown", sel + " == 2"},
		{"InterfaceUnusualState", "(" + sel + " != 1) != 2"},
	}
	for i, w := range want {
		if got := rules[i].Alert; got != w.alert {
			t.Errorf("rule %d alert: got %q, want %q", i, got, w.alert)
		}
		if got := rules[i].Expr; got != w.expr {
			t.Errorf("rule %d expr: got %q, want %q", i, got, w.expr)
		}
	}
}

func TestInterfaceSpeedRules(t *testing.T) {
	tests := []struct {
		name     string
		speed    *int32
		wantExpr string // empty means the interface should be skipped
	}{
		{"10G", ptr(10000), `ifHighSpeed{instance="sw1.example.com",ifName="et1"} != 10000`},
		{"1G", ptr(1000), `ifHighSpeed{instance="sw1.example.com",ifName="et1"} != 1000`},
		{"100M", ptr(100), `ifHighSpeed{instance="sw1.example.com",ifName="et1"} != 100`},
		{"25G", ptr(25000), `ifHighSpeed{instance="sw1.example.com",ifName="et1"} != 25000`},
		{"unset speed", nil, ""},
		// Read as Mbps, so a kbps-style value is now taken at face value
		// rather than divided. Netbox holding 10000000 means 10 Tbps here.
		{"kbps-style value is not converted", ptr(10000000), `ifHighSpeed{instance="sw1.example.com",ifName="et1"} != 10000000`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules := interfaceSpeedRules(
				[]netbox.Interface{testInterface(1, "sw1", "et1", tt.speed)},
				"monitoring-if-speed", "example.com",
			)
			if tt.wantExpr == "" {
				if got := len(rules); got != 0 {
					t.Fatalf("got %d rules, want 0", got)
				}
				return
			}
			if got, want := len(rules), 1; got != want {
				t.Fatalf("got %d rules, want %d", got, want)
			}
			if got, want := rules[0].Expr, tt.wantExpr; got != want {
				t.Errorf("expr: got %q, want %q", got, want)
			}
		})
	}
}

// TestMetricSelectorQuoting covers names that would otherwise break the PromQL
// selector.
func TestMetricSelectorQuoting(t *testing.T) {
	got := metricSelector("ifHighSpeed", `sw"1`, `Ethernet1/1`)
	want := `ifHighSpeed{instance="sw\"1",ifName="Ethernet1/1"}`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestRuleGroupsYAML shows the shape of the generated file.
func TestRuleGroupsYAML(t *testing.T) {
	groups := PromRuleGroups{Groups: []PromRuleGroup{
		{Name: "netbox_interface_up", Rules: interfaceUpRules(
			[]netbox.Interface{testInterface(1, "sw1", "Ethernet1/1", nil)}, "monitoring-if-up", "example.com")},
		{Name: "netbox_interface_speed", Rules: interfaceSpeedRules(
			[]netbox.Interface{testInterface(2, "sw1", "Ethernet1/1", ptr(10000000))}, "monitoring-if-speed", "example.com")},
	}}
	data, err := yaml.Marshal(&groups)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("\n%s", data)
}

func mtuIface(id, deviceID int32, device, name string, mtu *int32, enabled bool) netbox.Interface {
	i := testInterface(id, device, name, nil)
	i.Device.Id = deviceID
	i.Enabled = &enabled
	if mtu != nil {
		i.Mtu = *netbox.NewNullableInt32(mtu)
	}
	return i
}

func TestInterfaceMTURules(t *testing.T) {
	m9000, m1500 := int32(9000), int32(1500)
	platforms := map[int32]string{10: "eos", 11: "junos"}
	rules := interfaceMTURules([]netbox.Interface{
		mtuIface(1, 10, "sw1", "Ethernet1", &m9000, true),
		mtuIface(2, 10, "sw1", "Ethernet2", &m1500, true),
		mtuIface(3, 10, "sw1", "Ethernet3", nil, true),     // no MTU in Netbox
		mtuIface(4, 10, "sw1", "Ethernet4", &m9000, false), // disabled, exempt
		mtuIface(5, 11, "ex1", "xe-0/0/0", &m9000, true),   // junos, offset unknown
	}, platforms, "monitoring-if-up", "example.com")

	if got, want := len(rules), 2; got != want {
		t.Fatalf("got %d rules, want %d", got, want)
	}
	if got, want := rules[0].Expr, `ifMtu{instance="sw1.example.com",ifName="Ethernet1"} != 9000`; got != want {
		t.Errorf("expr: got %q, want %q", got, want)
	}
	if got, want := rules[0].Alert, "InterfaceMTUMismatch"; got != want {
		t.Errorf("alert: got %q, want %q", got, want)
	}
	if got, want := rules[1].Expr, `ifMtu{instance="sw1.example.com",ifName="Ethernet2"} != 1500`; got != want {
		t.Errorf("expr: got %q, want %q", got, want)
	}
}

// TestMTUOffsetEOS pins the measured EOS offset. Arista reports the payload
// MTU, the same number Netbox holds.
func TestMTUOffsetEOS(t *testing.T) {
	if got, ok := mtuOffsets["eos"]; !ok || got != 0 {
		t.Errorf("eos offset: got %d (present=%v), want 0", got, ok)
	}
	if _, ok := mtuOffsets["junos"]; ok {
		t.Error("junos has an offset, but its ifMtu convention has not been established")
	}
}

func TestInterfaceFlapRules(t *testing.T) {
	rules := interfaceFlapRules([]netbox.Interface{
		testInterface(1, "sw1", "Ethernet14/1", nil),
		testInterface(2, "", "Ethernet14/2", nil), // no device name, skipped
	}, "monitoring-if-up", "example.com")

	if got, want := len(rules), 1; got != want {
		t.Fatalf("got %d rules, want %d", got, want)
	}

	if got, want := rules[0].Alert, "InterfaceFlapping"; got != want {
		t.Errorf("alert: got %q, want %q", got, want)
	}
	want := `changes(ifOperStatus{instance="sw1.example.com",ifName="Ethernet14/1"}[1h]) > 3`
	if got := rules[0].Expr; got != want {
		t.Errorf("expr: got %q, want %q", got, want)
	}
	if got, want := rules[0].Labels["device"], "sw1"; got != want {
		t.Errorf("device label: got %q, want %q", got, want)
	}
	if got, want := rules[0].Labels["interface"], "Ethernet14/1"; got != want {
		t.Errorf("interface label: got %q, want %q", got, want)
	}
}

// A flapping interface recovers well before alertForUp elapses, so
// InterfaceDown cannot fire on it. The flap rule only adds anything if its own
// wait is shorter than the window it counts over; otherwise the alert would
// need the flapping to persist for longer than it takes to detect.
func TestFlapAlertOutlastsDownAlert(t *testing.T) {
	window, err := time.ParseDuration(flapWindow)
	if err != nil {
		t.Fatalf("flapWindow %q does not parse: %v", flapWindow, err)
	}
	wait, err := time.ParseDuration(alertForFlap)
	if err != nil {
		t.Fatalf("alertForFlap %q does not parse: %v", alertForFlap, err)
	}
	if wait >= window {
		t.Errorf("alertForFlap (%s) must be shorter than flapWindow (%s)", alertForFlap, flapWindow)
	}
	if flapThreshold < 1 {
		t.Errorf("flapThreshold is %d; a threshold below 1 fires on any single transition", flapThreshold)
	}
}

// The flap rule is driven by the same tag as the up rules, so an interface
// tagged for up-monitoring gets down, unusual-state and flapping coverage
// together.
func TestFlapRulesUseUpTag(t *testing.T) {
	ifaces := []netbox.Interface{testInterface(1, "sw1", "et1", nil)}

	alerts := map[string]bool{}
	for _, r := range append(interfaceUpRules(ifaces, "monitoring-if-up", "example.com"),
		interfaceFlapRules(ifaces, "monitoring-if-up", "example.com")...) {
		alerts[r.Alert] = true
	}
	for _, want := range []string{"InterfaceDown", "InterfaceUnusualState", "InterfaceFlapping"} {
		if !alerts[want] {
			t.Errorf("interface tagged monitoring-if-up did not produce %s", want)
		}
	}
}
