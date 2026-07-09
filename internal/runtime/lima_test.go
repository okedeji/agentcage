package runtime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Unit coverage only; real-VM integration tests are gated by a build tag.

func TestParseLimaStatus(t *testing.T) {
	cases := []struct {
		in   string
		want LimaStatus
	}{
		{"", LimaNonexistent},
		{"\n", LimaNonexistent},
		{"Running", LimaRunning},
		{"Running\n", LimaRunning},
		{"Stopped", LimaStopped},
		{"Stopped\n", LimaStopped},
		{"Broken", LimaUnknown},
		{"Initializing", LimaUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := parseLimaStatus(tc.in); got != tc.want {
				t.Errorf("parseLimaStatus(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestLimaStatus_String(t *testing.T) {
	cases := map[LimaStatus]string{
		LimaRunning:     "running",
		LimaStopped:     "stopped",
		LimaNonexistent: "nonexistent",
		LimaUnknown:     "unknown",
	}
	for status, want := range cases {
		if got := status.String(); got != want {
			t.Errorf("LimaStatus(%d).String() = %q, want %q", status, got, want)
		}
	}
}

func TestLimaVM_InstanceNameDefault(t *testing.T) {
	vm := &LimaVM{}
	if got := vm.instanceName(); got != DefaultLimaInstanceName {
		t.Errorf("instanceName() with empty field = %q, want default %q", got, DefaultLimaInstanceName)
	}
}

func TestLimaVM_InstanceNameOverride(t *testing.T) {
	vm := &LimaVM{InstanceName: "custom"}
	if got := vm.instanceName(); got != "custom" {
		t.Errorf("instanceName() with custom field = %q, want %q", got, "custom")
	}
}

func TestLimaVM_SocketAddressesUseHostSocketDir(t *testing.T) {
	vm := &LimaVM{HostSocketDir: "/x/y/sock"}
	if got := vm.ContainerdAddress(); got != "/x/y/sock/containerd.sock" {
		t.Errorf("ContainerdAddress = %q", got)
	}
	if got := vm.BuildKitAddress(); got != "unix:///x/y/sock/buildkitd.sock" {
		t.Errorf("BuildKitAddress = %q", got)
	}
}

func TestFindLimactl_PrefersBundledBinary(t *testing.T) {
	dir := t.TempDir()
	bundledDir := filepath.Join(dir, "lima")
	if err := os.MkdirAll(bundledDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	bundled := filepath.Join(bundledDir, "limactl")
	if err := os.WriteFile(bundled, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write bundled limactl: %v", err)
	}
	// os.Executable cannot be overridden here, so exercise the pure helper.
	if !isExecutable(bundled) {
		t.Errorf("isExecutable(%s) = false, want true", bundled)
	}
}

func TestIsExecutable_RejectsDirectory(t *testing.T) {
	if isExecutable(t.TempDir()) {
		t.Errorf("isExecutable returned true for a directory")
	}
}

func TestIsExecutable_RejectsNonExistent(t *testing.T) {
	if isExecutable(filepath.Join(t.TempDir(), "nope")) {
		t.Errorf("isExecutable returned true for nonexistent path")
	}
}

func TestIsExecutable_RejectsNonExecutableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if isExecutable(path) {
		t.Errorf("isExecutable returned true for non-executable file")
	}
}

func TestIsExecutable_AcceptsExecutableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x")
	if err := os.WriteFile(path, []byte("x"), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !isExecutable(path) {
		t.Errorf("isExecutable returned false for executable file")
	}
}

func TestExecutableDir_ReturnsADirectory(t *testing.T) {
	dir, ok := executableDir()
	if !ok {
		t.Fatal("executableDir should resolve the test binary")
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		t.Fatalf("executableDir returned %q, not a directory: %v", dir, err)
	}
}

// A Homebrew install invokes agentcage through a bin/ symlink into the Cellar;
// the companions sit next to the real binary. filepath.EvalSymlinks, which
// executableDir applies, must land on the real directory, not the link's.
func TestEvalSymlinks_ResolvesToRealDir(t *testing.T) {
	real := filepath.Join(t.TempDir(), "cellar")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	bin := filepath.Join(real, "agentcage")
	if err := os.WriteFile(bin, []byte("x"), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}
	linkDir := filepath.Join(t.TempDir(), "bin")
	if err := os.MkdirAll(linkDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	link := filepath.Join(linkDir, "agentcage")
	if err := os.Symlink(bin, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(link)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	// Compare against the fully-resolved real dir: t.TempDir on macOS sits
	// under /var, itself a symlink to /private/var, which EvalSymlinks also
	// collapses. The point is that the link lands on the cellar, not linkDir.
	wantReal, _ := filepath.EvalSymlinks(real)
	if got := filepath.Dir(resolved); got != wantReal {
		t.Errorf("resolved dir = %q, want the real cellar %q", got, wantReal)
	}
}

func TestFindLimactl_ErrorMessageNamesPaths(t *testing.T) {
	// Clear PATH to force a miss; if the environment still finds a bundled
	// limactl the test skips.
	origPath := os.Getenv("PATH")
	t.Cleanup(func() { _ = os.Setenv("PATH", origPath) })
	_ = os.Setenv("PATH", "")

	_, err := FindLimactl()
	if err == nil {
		t.Skip("FindLimactl succeeded; environment unexpectedly has limactl bundled")
	}
	if !strings.Contains(err.Error(), "agentcage init") {
		t.Errorf("error message should point at remediation, got: %v", err)
	}
}
