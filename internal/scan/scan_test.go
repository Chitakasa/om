package scan

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestScanMatchesPython(t *testing.T) {
	b, _ := os.ReadFile("../../testdata/golden/small_modules.json")
	var m map[string]json.RawMessage
	json.Unmarshal(b, &m)
	var cases []struct {
		Tool, In string
		Out      any
	}
	d := json.NewDecoder(bytes.NewReader(m["scan"]))
	d.UseNumber()
	d.Decode(&cases)
	for _, c := range cases {
		got, err := Count(c.Tool, c.In)
		if s, ok := c.Out.(string); ok && strings.HasPrefix(s, "PYEXC") {
			if err == nil {
				t.Errorf("%s %q: python raised %s, Go answered %v", c.Tool, c.In, s, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s %q: %v", c.Tool, c.In, err)
			continue
		}
		want := map[string]int{}
		for k, v := range c.Out.(map[string]any) {
			n, _ := v.(json.Number).Int64()
			want[k] = int(n)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s %q: %v want %v", c.Tool, c.In, got, want)
		}
	}
	var cmds map[string][]string
	json.Unmarshal(m["scan_cmd"], &cmds)
	for tool, want := range cmds {
		if got := Command(tool, "img:1"); !reflect.DeepEqual(got, want) {
			t.Errorf("Command(%s) %v want %v", tool, got, want)
		}
	}
	if Scanner(func(n string) (string, error) {
		if n == "grype" {
			return "/x/grype", nil
		}
		return "", os.ErrNotExist
	}) != "grype" || Scanner(func(string) (string, error) { return "", os.ErrNotExist }) != "" {
		t.Error("Scanner")
	}
}
