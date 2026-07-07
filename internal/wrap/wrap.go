// Package wrap generates the Agentfile that turns an existing MCP server into an
// agentcage agent. It maps how a server is distributed (an npm or PyPI package,
// or an OCI image) to a FROM/RUN/ENTRYPOINT that installs and launches it over
// stdio, so an import is an ordinary build against a generated Agentfile the
// operator then owns.
package wrap

import (
	"fmt"
	"sort"
	"strings"
)

// Registry types wrap can generate an Agentfile for. A package distributed any
// other way (cargo, nuget, mcpb) is refused, named, rather than wrapped wrong.
const (
	NPM  = "npm"
	PyPI = "pypi"
	OCI  = "oci"
)

// Base images are pinned to a concrete tag, not a floating one, so a wrapped
// agent rebuilds to the same bytes instead of drifting when node:slim moves.
const (
	npmBase  = "node:22-slim"
	pypiBase = "python:3.12-slim"
)

// NPMLauncherFile is the offline launcher written beside an npm import's
// Agentfile and run as its ENTRYPOINT. The import copies NPMLauncherScript into
// the tool-collection directory under this name.
const NPMLauncherFile = "npm-entry.sh"

// npmLauncher resolves a globally-installed npm package's bin from its own
// package.json and execs node on it. It replaces `npx <pkg>`, which pings the
// registry on every start and hangs in a deny-default cage. It is package
// agnostic: the package identifier is passed as $1, and the global modules path
// is derived from node itself, so it needs no network and no npm invocation.
const npmLauncher = `#!/bin/sh
set -e
main=$(node -e 'const p=require("path");const d=p.join(p.dirname(process.execPath),"..","lib","node_modules",process.argv[1]);const b=require(d+"/package.json").bin;const r=typeof b==="string"?b:b[Object.keys(b)[0]];process.stdout.write(p.resolve(d,r))' "$1")
exec node "$main"
`

// NPMLauncherScript is the launcher's contents, written into an npm import's
// tool-collection directory so COPY . /agent carries it into the image.
func NPMLauncherScript() string { return npmLauncher }

// The imported server speaks MCP over stdio; a USES sub-agent is reached over
// HTTP. So the ENTRYPOINT is not the server directly but the agentcage bridge
// wrapping it: as a sub-agent the bridge serves HTTP and forwards to the server,
// as a root it execs the server. BridgeBinaryName is the static agentcage binary
// the import writes beside the Agentfile (COPY . /agent lands it next to the
// WORKDIR, hence ./); BridgeSubcommand is the verb that runs the bridge.
const (
	BridgeBinaryName = "agentcage"
	BridgeSubcommand = "mcp-bridge"
)

// EnvVar is an input the wrapped server declares. A secret becomes a SECRETS
// line so its value is injected at runtime and never baked into the image; a
// plain one becomes ENV, with the author default when the entry gives one.
// Description, when present, is written as a comment above the line so the
// generated Agentfile explains what each input is for.
type EnvVar struct {
	Name        string
	Secret      bool
	Required    bool
	Default     string
	Description string
}

// Source is how a foreign MCP server is distributed, enough to generate its
// Agentfile. Launch overrides the derived ENTRYPOINT and is required for OCI,
// whose launch command wrap cannot infer.
type Source struct {
	Registry   string
	Identifier string
	Version    string
	Launch     []string
	Env        []EnvVar
	// Origin is the canonical identity of the wrapped server, stamped as
	// META imported_from so a wrapper is recognizable as "the wrapped X" across
	// rebuilds and across users. Empty leaves the marker off.
	Origin string
}

// CanonicalOrigin is the version-less identity of the wrapped server used as the
// imported_from marker: the package coordinate, so every wrap of the same server
// carries the same marker regardless of version. A registry import overrides this
// with the server's reverse-DNS name, which is why it is a Source field, not
// always derived.
func CanonicalOrigin(src Source) string {
	return src.Registry + ":" + src.Identifier
}

// Agentfile renders the Agentfile wrapping src, or an error when src cannot be
// wrapped: an unsupported registry type, or an OCI image with no launch command.
func Agentfile(src Source) (string, error) {
	if src.Identifier == "" {
		return "", fmt.Errorf("wrap: no package identifier")
	}
	switch src.Registry {
	case NPM:
		// Not npx: npx re-checks the registry on every start (even --no-install), and
		// a cage is egress-denied, so that check hangs until it times out. The
		// launcher resolves the globally-installed package's bin and execs it
		// directly, entirely offline. See NPMLauncherScript.
		return render(fromLine(npmBase), runLine("npm install -g "+spec(src, "@")), src, []string{"sh", NPMLauncherFile, src.Identifier})
	case PyPI:
		return render(fromLine(pypiBase), runLine("pip install --no-cache-dir "+spec(src, "==")), src, []string{src.Identifier})
	case OCI:
		if len(src.Launch) == 0 {
			return "", fmt.Errorf("cannot wrap oci image %s: its launch command is unknown; pass --entrypoint", src.Identifier)
		}
		return render(fromLine(ociImage(src)), "", src, nil)
	default:
		return "", fmt.Errorf("cannot wrap a %q package; import supports npm, pypi, and oci", src.Registry)
	}
}

// render assembles the Agentfile from its base line, an optional build line, the
// declared inputs, and an entrypoint (src.Launch when set, else defaultLaunch).
func render(from, run string, src Source, defaultLaunch []string) (string, error) {
	launch := src.Launch
	if len(launch) == 0 {
		launch = defaultLaunch
	}
	if len(launch) == 0 {
		return "", fmt.Errorf("wrap: no entrypoint for %s", src.Identifier)
	}

	lines := []string{from}
	if run != "" {
		lines = append(lines, run)
	}
	lines = append(lines, envLines(src.Env)...)
	// The marker that lets a later import recognize this as an existing wrapper
	// of the same server, its own or someone else's, and offer to reuse it.
	if src.Origin != "" {
		lines = append(lines, "META imported_from "+src.Origin)
	}
	// Expose every tool the wrapped server serves; narrow to specific names to
	// restrict the surface. Without this the tool collection would be private
	// and nothing could call it.
	lines = append(lines, "EXPOSE *")
	lines = append(lines, "ENTRYPOINT "+bridgeEntrypoint(launch))
	return strings.Join(lines, "\n") + "\n", nil
}

// bridgeEntrypoint wraps the server's launch command with the bridge, so the
// wrapped collection serves over HTTP as a sub-agent and over stdio as a root.
func bridgeEntrypoint(launch []string) string {
	return "./" + BridgeBinaryName + " " + BridgeSubcommand + " -- " + strings.Join(launch, " ")
}

// envLines renders the declared inputs, sorted so a re-import of the same server
// produces the same Agentfile.
func envLines(env []EnvVar) []string {
	sorted := append([]EnvVar(nil), env...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	var lines []string
	for _, e := range sorted {
		if e.Description != "" {
			lines = append(lines, "# "+strings.ReplaceAll(e.Description, "\n", " "))
		}
		switch {
		case e.Secret:
			lines = append(lines, "SECRETS "+e.Name)
		case e.Default != "":
			lines = append(lines, "ENV "+e.Name+"="+e.Default)
		default:
			lines = append(lines, "ENV "+e.Name)
		}
	}
	return lines
}

func fromLine(base string) string { return "FROM " + base }
func runLine(cmd string) string   { return "RUN " + cmd }

// spec joins an identifier and version with the package manager's pin separator
// ("@" for npm, "==" for pip), or leaves the identifier bare when unversioned.
func spec(src Source, sep string) string {
	if src.Version == "" {
		return src.Identifier
	}
	return src.Identifier + sep + src.Version
}

// ociImage renders the FROM reference, pinning by digest when the version is one
// and by tag otherwise.
func ociImage(src Source) string {
	switch {
	case src.Version == "":
		return src.Identifier
	case strings.HasPrefix(src.Version, "sha256:"):
		return src.Identifier + "@" + src.Version
	default:
		return src.Identifier + ":" + src.Version
	}
}
