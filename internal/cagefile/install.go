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
		if err := installNodeDeps(ctx, manifest, agentDir, sdkTarball, progress); err != nil {
			return err
		}
	case "python3":
		if err := installPythonDeps(ctx, manifest, agentDir, progress); err != nil {
			return err
		}
	case "go":
		if err := installGoDeps(ctx, manifest, agentDir, progress); err != nil {
			return err
		}
	case "static":
		progress("static runtime, no dependencies to install")
	default:
		return fmt.Errorf("unsupported runtime: %s", manifest.Runtime)
	}

	if manifest.Build != "" {
		if err := runBuild(ctx, manifest, agentDir, progress); err != nil {
			return err
		}
	}
	return nil
}

func runBuild(ctx context.Context, manifest *Manifest, agentDir string, progress func(string)) error {
	progress("build: " + manifest.Build)
	parts := strings.Fields(manifest.Build)
	cmd := exec.CommandContext(ctx, parts[0], parts[1:]...)
	cmd.Dir = agentDir
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("build failed: %w\n%s", err, out)
	}
	progress("build complete")
	return nil
}

func installNodeDeps(ctx context.Context, manifest *Manifest, agentDir, sdkTarball string, progress func(string)) error {
	hasPkgJSON := fileExistsAt(filepath.Join(agentDir, "package.json"))

	if !hasPkgJSON && len(manifest.NpmDeps) == 0 {
		progress("no package.json and no npm dependencies declared")
		return nil
	}

	// If no package.json but Cagefile lists npm deps, generate one.
	if !hasPkgJSON {
		progress("generating package.json from Cagefile")
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
	}

	// Rewrite @agentcage/sdk to resolve from local tarball so
	// npm install works without registry access.
	if sdkTarball != "" {
		if err := rewriteSDKDep(agentDir, sdkTarball); err != nil {
			progress("warning: could not rewrite SDK dep: " + err.Error())
		}
	}

	progress("npm install")
	cmd := exec.CommandContext(ctx, "npm", "install", "--no-audit", "--no-fund")
	cmd.Dir = agentDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("npm install failed: %w\n%s", err, out)
	}

	progress("npm install complete")
	return nil
}

// rewriteSDKDep patches @agentcage/sdk in package.json to point to
// the local tarball. Reads the existing package.json, modifies the
// dep, writes it back.
func rewriteSDKDep(agentDir, sdkTarball string) error {
	pkgPath := filepath.Join(agentDir, "package.json")
	data, err := os.ReadFile(pkgPath)
	if err != nil {
		return err
	}

	var pkg map[string]any
	if err := json.Unmarshal(data, &pkg); err != nil {
		return err
	}

	deps, ok := pkg["dependencies"].(map[string]any)
	if !ok {
		return nil
	}
	if _, hasDep := deps["@agentcage/sdk"]; !hasDep {
		return nil
	}

	absTarball, _ := filepath.Abs(sdkTarball)
	deps["@agentcage/sdk"] = "file:" + absTarball
	pkg["dependencies"] = deps
	out, err := json.MarshalIndent(pkg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(pkgPath, out, 0644)
}

func fileExistsAt(path string) bool {
	_, err := os.Stat(path)
	return err == nil
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
