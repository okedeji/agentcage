package runtime

import (
	"reflect"
	"testing"
)

func TestParseImageLaunch(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{`["/server/github-mcp-server"]` + "\t" + `["stdio"]`, []string{"/server/github-mcp-server", "stdio"}},
		{`null` + "\t" + `["node","server.js"]`, []string{"node", "server.js"}},
		{`["/bin/app"]` + "\t" + `null`, []string{"/bin/app"}},
	}
	for _, c := range cases {
		got, err := parseImageLaunch(c.in)
		if err != nil {
			t.Fatalf("parseImageLaunch(%q): %v", c.in, err)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("parseImageLaunch(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
