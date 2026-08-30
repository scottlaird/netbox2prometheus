package main

import (
	"testing"

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
		{"10G", ptr(10000000), `ifHighSpeed{instance="sw1.example.com",ifName="et1"} != 10000`},
		{"1G", ptr(1000000), `ifHighSpeed{instance="sw1.example.com",ifName="et1"} != 1000`},
		{"100M", ptr(100000), `ifHighSpeed{instance="sw1.example.com",ifName="et1"} != 100`},
		{"25G", ptr(25000000), `ifHighSpeed{instance="sw1.example.com",ifName="et1"} != 25000`},
		{"unset speed", nil, ""},
		{"not a whole Mbps", ptr(1544), ""},
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
