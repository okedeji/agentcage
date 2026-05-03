package cagefile

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// InstallDependencies installs runtime dependencies declared in the
// manifest into the agent directory. The sdkTarball path points to a
// local @agentcage/sdk npm tarball for offline resolution.
func InstallDependencies(ctx context.Context, manifest *Manifest, agentDir, sdkTarball string, progress func(string)) error {
	switch manifest.Runtime {
	case "node":
		return installNodeDeps(ctx, manifest, agentDir, sdkTarball, progress)
	case "python3":
		return installPythonDeps(ctx, manifest, agentDir, progress)
	case "go":
		return installGoDeps(ctx, manifest, agentDir, progress)
	case "static":
		progress("static runtime, no dependencies to install")
		return nil
	default:
		return fmt.Errorf("unsupported runtime: %s", manifest.Runtime)
	}
}

func installNodeDeps(ctx context.Context, manifest *Manifest, agentDir, sdkTarball string, progress func(string)) error {
	if len(manifest.NpmDeps) == 0 {
		progress("no npm dependencies declared")
		return nil
	}

	progress("writing package.json")

	// Build package.json from manifest deps.
	deps := make(map[string]string, len(manifest.NpmDeps))
	for _, dep := range manifest.NpmDeps {
		name, version := splitNpmDep(dep)
		deps[name] = version
	}

	pkg := map[string]any{
		"name":         "agentcage-build",
		"version":      "1.0.0",
		"private":      true,
		"dependencies": deps,
	}
	pkgJSON, err := json.MarshalIndent(pkg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling package.json: %w", err)
	}
	if err := os.WriteFile(filepath.Join(agentDir, "package.json"), pkgJSON, 0644); err != nil {
		return fmt.Errorf("writing package.json: %w", err)
	}

	// Write .npmrc to resolve @agentcage/sdk from local tarball.
	if sdkTarball != "" {
		npmrc := fmt.Sprintf("@agentcage:registry=file://%s\n", filepath.Dir(sdkTarball))
		if err := os.WriteFile(filepath.Join(agentDir, ".npmrc"), []byte(npmrc), 0644); err != nil {
			return fmt.Errorf("writing .npmrc: %w", err)
		}

		// Also rewrite the SDK dep to point to the tarball directly
		// since file: registries don't work like real registries.
		if _, ok := deps["@agentcage/sdk"]; ok {
			deps["@agentcage/sdk"] = "file:" + sdkTarball
			pkg["dependencies"] = deps
			pkgJSON, _ = json.MarshalIndent(pkg, "", "  ")
			_ = os.WriteFile(filepath.Join(agentDir, "package.json"), pkgJSON, 0644)
		}
	}

	progress("npm install")
	cmd := exec.CommandContext(ctx, "npm", "install", "--production", "--no-audit", "--no-fund")
	cmd.Dir = agentDir
	cmd.Env = append(os.Environ(), "NODE_ENV=production")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("npm install failed: %w\n%s", err, out)
	}

	progress("npm install complete")
	return nil
}

func installPythonDeps(ctx context.Context, manifest *Manifest, agentDir string, progress func(string)) error {
	if len(manifest.PipDeps) == 0 {
		progress("no pip dependencies declared")
		return nil
	}

	progress("writing requirements.txt")

	reqFile := filepath.Join(agentDir, "requirements.txt")
	content := strings.Join(manifest.PipDeps, "\n") + "\n"
	if err := os.WriteFile(reqFile, []byte(content), 0644); err != nil {
		return fmt.Errorf("writing requirements.txt: %w", err)
	}

	vendorDir := filepath.Join(agentDir, "vendor")
	if err := os.MkdirAll(vendorDir, 0755); err != nil {
		return fmt.Errorf("creating vendor dir: %w", err)
	}

	progress("pip install")
	cmd := exec.CommandContext(ctx, "pip", "install",
		"--target", vendorDir,
		"--no-cache-dir",
		"-r", reqFile,
	)
	cmd.Dir = agentDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pip install failed: %w\n%s", err, out)
	}

	progress("pip install complete")
	return nil
}

func installGoDeps(ctx context.Context, manifest *Manifest, agentDir string, progress func(string)) error {
	if len(manifest.GoDeps) == 0 {
		progress("no go dependencies declared")
		return nil
	}

	progress("go build")
	for _, dep := range manifest.GoDeps {
		cmd := exec.CommandContext(ctx, "go", "install", dep)
		cmd.Dir = agentDir
		cmd.Env = append(os.Environ(), "GOBIN="+filepath.Join(agentDir, "bin"))
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("go install %s failed: %w\n%s", dep, err, out)
		}
	}

	progress("go build complete")
	return nil
}

// splitNpmDep splits "@scope/name@version" or "name@version" into name and version.
func splitNpmDep(dep string) (string, string) {
	// Handle scoped packages: @scope/name@version
	if strings.HasPrefix(dep, "@") {
		afterScope := strings.Index(dep[1:], "@")
		if afterScope == -1 {
			return dep, "*"
		}
		idx := afterScope + 1
		return dep[:idx], dep[idx+1:]
	}
	// Handle normal packages: name@version
	idx := strings.LastIndex(dep, "@")
	if idx <= 0 {
		return dep, "*"
	}
	return dep[:idx], dep[idx+1:]
}
