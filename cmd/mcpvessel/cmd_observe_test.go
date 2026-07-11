package main

import "testing"

func TestParseObservedHost(t *testing.T) {
	cases := map[string]string{
		"egress observed: api.github.com (agent github)":           "api.github.com",
		"egress observed: objects.githubusercontent.com (agent x)": "objects.githubusercontent.com",
		"some other log line": "",
		"egress denied: api.github.com (agent github) — ...": "", // denial, not observation
	}
	for line, want := range cases {
		got, ok := parseObservedHost(line)
		if want == "" {
			if ok {
				t.Errorf("parseObservedHost(%q) = %q, want no match", line, got)
			}
			continue
		}
		if !ok || got != want {
			t.Errorf("parseObservedHost(%q) = %q,%v want %q", line, got, ok, want)
		}
	}
}
