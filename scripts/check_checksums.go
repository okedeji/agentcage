//go:build ignore

// check_checksums.go verifies that the checksums embedded in download.go match
// the actual SHA-256 hashes of the asset files in a given directory.
//
// Usage: go run scripts/check_checksums.go <assets-dir>
package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: go run scripts/check_checksums.go <assets-dir>")
		os.Exit(1)
	}
	assetsDir := os.Args[1]

	data, err := os.ReadFile("internal/vm/download.go")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	content := string(data)

	// Parse active (uncommented) checksum entries from download.go.
	// Matches: "filename": "hexdigest",
	re := regexp.MustCompile(`(?m)^\s+"([^"]+)"\s*:\s*"([a-f0-9]{64})\s*"`)
	matches := re.FindAllStringSubmatch(content, -1)

	embedded := make(map[string]string)
	for _, m := range matches {
		line := strings.TrimSpace(m[0])
		if strings.HasPrefix(line, "//") {
			continue
		}
		embedded[m[1]] = m[2]
	}

	if len(embedded) == 0 {
		fmt.Fprintln(os.Stderr, "error: no checksums found in internal/vm/download.go")
		fmt.Fprintln(os.Stderr, "Run: ./scripts/embed-checksums.sh <assets-dir>")
		os.Exit(1)
	}

	// Verify each embedded checksum against the actual asset file.
	errors := 0
	for name, expected := range embedded {
		path := assetsDir + "/" + name
		actual, err := hashFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL  %s: %v\n", name, err)
			errors++
			continue
		}
		if actual != expected {
			fmt.Fprintf(os.Stderr, "FAIL  %s: embedded=%s actual=%s\n", name, expected, actual)
			errors++
			continue
		}
		fmt.Printf("OK    %s\n", name)
	}

	if errors > 0 {
		fmt.Fprintf(os.Stderr, "\n%d checksum(s) failed. Re-run: ./scripts/embed-checksums.sh %s\n", errors, assetsDir)
		os.Exit(1)
	}
	fmt.Printf("\nAll %d checksum(s) verified.\n", len(embedded))
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("opening file: %w", err)
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("reading file: %w", err)
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
