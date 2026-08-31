package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "netbox2prometheus.yaml")
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatalf("writing test config: %v", err)
	}
	return path
}

const minimalConfig = `
config:
  netbox:
    host: "https://netbox.example.com"
    token: "sekrit"
`

// TestConfigICMPCount covers a field that silently fell back to its zero value
// for as long as it existed: the struct tag read "jcon" rather than "json", so
// the decoder never matched icmp_count and every generated network_exporter
// config carried "count: 0" instead of the configured value.
func TestConfigICMPCount(t *testing.T) {
	tests := []struct {
		name string
		body string
		want int
	}{
		{"explicit", minimalConfig + "  icmp_count: 3\n", 3},
		{"schema default applies when unset", minimalConfig, 6},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := ParseConfig(writeConfig(t, tt.body))
			if err != nil {
				t.Fatalf("ParseConfig: %v", err)
			}
			if got := cfg.ICMPCount; got != tt.want {
				t.Errorf("ICMPCount: got %d, want %d", got, tt.want)
			}
		})
	}
}

// The decoder matches on json tags, so a field carrying any other tag name is
// silently never populated. That is not a compile error and not a parse error;
// it shows up only as a wrong value in a generated file. Check the whole struct
// rather than the one field that happened to be wrong.
func TestConfigFieldsHaveJSONTags(t *testing.T) {
	var walk func(t reflect.Type, path string)
	walk = func(rt reflect.Type, path string) {
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			if f.PkgPath != "" {
				continue // unexported
			}
			name := path + f.Name
			if _, ok := f.Tag.Lookup("json"); !ok {
				t.Errorf("%s has no json tag (tag is %q); the config decoder will never populate it", name, f.Tag)
			}
			if f.Type.Kind() == reflect.Struct {
				walk(f.Type, name+".")
			}
		}
	}
	walk(reflect.TypeOf(Config{}), "")
}

// Every json tag must correspond to a field the cue schema actually defines,
// or the value is dropped on the floor the same way.
func TestConfigTagsMatchSchema(t *testing.T) {
	schema := string(cueSchema)
	rt := reflect.TypeOf(Config{})
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		tag, ok := f.Tag.Lookup("json")
		if !ok {
			continue // reported by TestConfigFieldsHaveJSONTags
		}
		key := strings.Split(tag, ",")[0]
		if key == "" || key == "-" {
			continue
		}
		if !strings.Contains(schema, key+":") {
			t.Errorf("field %s has json tag %q, which config.cue does not define", f.Name, key)
		}
	}
}
