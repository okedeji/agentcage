package wrap

import (
	"strings"
	"testing"
)

func TestVesselfile_NPM(t *testing.T) {
	got, err := Vesselfile(Source{Registry: NPM, Identifier: "@modelcontextprotocol/server-filesystem", Version: "1.0"})
	if err != nil {
		t.Fatalf("Vesselfile: %v", err)
	}
	wantContains := []string{
		"FROM node:22-slim",
		"RUN npm install -g @modelcontextprotocol/server-filesystem@1.0",
		"EXPOSE *",
		`ENTRYPOINT ["./mcpvessel","mcp-bridge","--","sh","npm-entry.sh","@modelcontextprotocol/server-filesystem"]`,
	}
	for _, w := range wantContains {
		if !strings.Contains(got, w) {
			t.Errorf("Vesselfile missing %q; got:\n%s", w, got)
		}
	}
}

func TestVesselfile_EgressAllow(t *testing.T) {
	got, err := Vesselfile(Source{
		Registry:   PyPI,
		Identifier: "mcp-server-fetch",
		Egress:     []string{"api.github.com", "objects.githubusercontent.com"},
	})
	if err != nil {
		t.Fatalf("Vesselfile: %v", err)
	}
	if !strings.Contains(got, "EGRESS allow:api.github.com,objects.githubusercontent.com") {
		t.Errorf("missing joined EGRESS line; got:\n%s", got)
	}
}

func TestVesselfile_NoEgressByDefault(t *testing.T) {
	got, err := Vesselfile(Source{Registry: PyPI, Identifier: "mcp-server-time"})
	if err != nil {
		t.Fatalf("Vesselfile: %v", err)
	}
	if strings.Contains(got, "EGRESS") {
		t.Errorf("expected no EGRESS line by default; got:\n%s", got)
	}
}

func TestVesselfile_PyPIWithEnvAndSecret(t *testing.T) {
	got, err := Vesselfile(Source{
		Registry:   PyPI,
		Identifier: "mcp-server-fetch",
		Env: []EnvVar{
			{Name: "USER_AGENT", Default: "mcpvessel"},
			{Name: "API_KEY", Secret: true},
			{Name: "BASE_URL"},
		},
	})
	if err != nil {
		t.Fatalf("Vesselfile: %v", err)
	}
	for _, w := range []string{
		"FROM python:3.12-slim",
		"RUN pip install --no-cache-dir mcp-server-fetch\n",
		"SECRETS API_KEY",
		"ENV USER_AGENT=mcpvessel",
		"ENV BASE_URL\n",
		`ENTRYPOINT ["./mcpvessel","mcp-bridge","--","mcp-server-fetch"]`,
	} {
		if !strings.Contains(got, w) {
			t.Errorf("Vesselfile missing %q; got:\n%s", w, got)
		}
	}
}

func TestVesselfile_StampsOriginMarker(t *testing.T) {
	got, err := Vesselfile(Source{Registry: NPM, Identifier: "@scope/srv", Origin: "npm:@scope/srv"})
	if err != nil {
		t.Fatalf("Vesselfile: %v", err)
	}
	if !strings.Contains(got, "META imported_from npm:@scope/srv") {
		t.Errorf("Vesselfile missing the imported_from marker; got:\n%s", got)
	}

	// No origin, no marker.
	bare, err := Vesselfile(Source{Registry: NPM, Identifier: "@scope/srv"})
	if err != nil {
		t.Fatalf("Vesselfile: %v", err)
	}
	if strings.Contains(bare, "imported_from") {
		t.Errorf("Vesselfile stamped a marker with no origin; got:\n%s", bare)
	}
}

func TestCanonicalOrigin(t *testing.T) {
	got := CanonicalOrigin(Source{Registry: PyPI, Identifier: "mcp-server-time", Version: "1.2"})
	if got != "pypi:mcp-server-time" {
		t.Errorf("CanonicalOrigin = %q, want the version-less coordinate", got)
	}
}

func TestVesselfile_DescribesInputs(t *testing.T) {
	got, err := Vesselfile(Source{
		Registry:   PyPI,
		Identifier: "srv",
		Env:        []EnvVar{{Name: "API_KEY", Secret: true, Description: "The service API key."}},
	})
	if err != nil {
		t.Fatalf("Vesselfile: %v", err)
	}
	if !strings.Contains(got, "# The service API key.\nSECRETS API_KEY") {
		t.Errorf("Vesselfile does not document the input; got:\n%s", got)
	}
}

func TestVesselfile_OCINeedsLaunch(t *testing.T) {
	if _, err := Vesselfile(Source{Registry: OCI, Identifier: "ghcr.io/acme/mcp", Version: "1.2"}); err == nil {
		t.Fatal("want an error: oci wrap has no launch command")
	}
	got, err := Vesselfile(Source{Registry: OCI, Identifier: "ghcr.io/acme/mcp", Version: "1.2", Launch: []string{"mcp-slack", "--stdio"}})
	if err != nil {
		t.Fatalf("Vesselfile: %v", err)
	}
	if !strings.Contains(got, "FROM ghcr.io/acme/mcp:1.2") || !strings.Contains(got, `ENTRYPOINT ["./mcpvessel","mcp-bridge","--","mcp-slack","--stdio"]`) {
		t.Errorf("oci Vesselfile wrong; got:\n%s", got)
	}
}

func TestVesselfile_UnsupportedRegistry(t *testing.T) {
	if _, err := Vesselfile(Source{Registry: "cargo", Identifier: "x"}); err == nil {
		t.Fatal("want an error for an unsupported registry type")
	}
}

func TestParseCoordinate(t *testing.T) {
	cases := []struct {
		in         string
		wantOK     bool
		reg, id, v string
	}{
		{"npm:@modelcontextprotocol/server-filesystem@1.0", true, NPM, "@modelcontextprotocol/server-filesystem", "1.0"},
		{"npm:@scope/pkg", true, NPM, "@scope/pkg", ""},
		{"npm:plain@2.3", true, NPM, "plain", "2.3"},
		{"pypi:mcp-server-fetch==0.2", true, PyPI, "mcp-server-fetch", "0.2"},
		{"oci:ghcr.io/acme/mcp:1.2", true, OCI, "ghcr.io/acme/mcp", "1.2"},
		{"oci:ghcr.io/acme/mcp@sha256:abc", true, OCI, "ghcr.io/acme/mcp", "sha256:abc"},
		{"io.github.user/server", false, "", "", ""},
		{"ghcr.io/org/name:1.0", false, "", "", ""},
	}
	for _, c := range cases {
		src, ok, err := ParseCoordinate(c.in)
		if err != nil {
			t.Fatalf("ParseCoordinate(%q): %v", c.in, err)
		}
		if ok != c.wantOK {
			t.Errorf("ParseCoordinate(%q) ok = %v, want %v", c.in, ok, c.wantOK)
			continue
		}
		if ok && (src.Registry != c.reg || src.Identifier != c.id || src.Version != c.v) {
			t.Errorf("ParseCoordinate(%q) = %+v, want reg=%q id=%q v=%q", c.in, src, c.reg, c.id, c.v)
		}
	}
}
