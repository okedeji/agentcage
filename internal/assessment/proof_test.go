package assessment

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeTestProof(t *testing.T, dir, filename, content string) {
	t.Helper()
	err := os.WriteFile(filepath.Join(dir, filename), []byte(content), 0644)
	require.NoError(t, err)
}

const validProofYAML = `vulnerability_class: sqli
validation_type: time_based
description: Test proof
payload_template:
  method: GET
  url: "http://example.com"
  parameter: id
  value: "1' OR SLEEP(5)--"
confirmation:
  type: response_time_delta
  expected_delta_ms: 4500
  tolerance_ms: 1000
max_requests: 5
max_duration_seconds: 30
safety_classification:
  destructive: false
  data_exfiltration: false
  state_modification: false
  rationale: Time delay only
`

const secondProofYAML = `vulnerability_class: sqli
validation_type: error_based
description: Error based test
payload_template:
  method: GET
  url: "http://example.com"
  parameter: id
  value: "1'"
confirmation:
  type: response_contains
  expected_pattern: "(SQL|syntax)"
max_requests: 3
max_duration_seconds: 30
safety_classification:
  destructive: false
  data_exfiltration: false
  state_modification: false
  rationale: Syntax error only
`

const xssProofYAML = `vulnerability_class: xss
validation_type: reflected
description: XSS test
payload_template:
  method: GET
  url: "http://example.com"
  parameter: q
  value: "<script>alert(1)</script>"
confirmation:
  type: response_contains
  expected_pattern: "<script>"
max_requests: 3
max_duration_seconds: 30
safety_classification:
  destructive: false
  data_exfiltration: false
  state_modification: false
  rationale: Browser-side only
`

func TestLoadProofs(t *testing.T) {
	dir := t.TempDir()
	writeTestProof(t, dir, "sqli_time.yaml", validProofYAML)
	writeTestProof(t, dir, "sqli_error.yaml", secondProofYAML)
	writeTestProof(t, dir, "xss_reflected.yaml", xssProofYAML)

	lib, err := LoadProofs(dir)
	require.NoError(t, err)
	assert.Len(t, lib.List(), 3)
}

func TestLoadProofs_FromRealDirectory(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	proofDir := filepath.Join(repoRoot, "proofs", "validation")

	if _, err := os.Stat(proofDir); os.IsNotExist(err) {
		t.Skip("proof directory not found, skipping")
	}

	lib, err := LoadProofs(proofDir)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(lib.List()), 8)
}

func TestGet(t *testing.T) {
	dir := t.TempDir()
	writeTestProof(t, dir, "sqli_time.yaml", validProofYAML)

	lib, err := LoadProofs(dir)
	require.NoError(t, err)

	pb, err := lib.Get("sqli", "time_based")
	require.NoError(t, err)
	assert.Equal(t, "sqli", pb.VulnClass)
	assert.Equal(t, "time_based", pb.ValidationType)
	assert.Equal(t, 5, pb.MaxRequests)
	assert.Equal(t, "response_time_delta", pb.Confirmation.Type)
	assert.Equal(t, 4500, pb.Confirmation.ExpectedDeltaMS)
}

func TestGet_UnknownVulnClass(t *testing.T) {
	dir := t.TempDir()
	writeTestProof(t, dir, "sqli_time.yaml", validProofYAML)

	lib, err := LoadProofs(dir)
	require.NoError(t, err)

	_, err = lib.Get("nosuch", "time_based")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrProofNotFound))
}

func TestGet_UnknownValidationType(t *testing.T) {
	dir := t.TempDir()
	writeTestProof(t, dir, "sqli_time.yaml", validProofYAML)

	lib, err := LoadProofs(dir)
	require.NoError(t, err)

	_, err = lib.Get("sqli", "nosuch")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrProofNotFound))
}

func TestGetByVulnClass(t *testing.T) {
	dir := t.TempDir()
	writeTestProof(t, dir, "sqli_time.yaml", validProofYAML)
	writeTestProof(t, dir, "sqli_error.yaml", secondProofYAML)
	writeTestProof(t, dir, "xss_reflected.yaml", xssProofYAML)

	lib, err := LoadProofs(dir)
	require.NoError(t, err)

	sqliProofs := lib.GetByVulnClass("sqli")
	assert.Len(t, sqliProofs, 2)

	xssProofs := lib.GetByVulnClass("xss")
	assert.Len(t, xssProofs, 1)

	noneProofs := lib.GetByVulnClass("nosuch")
	assert.Empty(t, noneProofs)
}

func TestLoadProofs_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	writeTestProof(t, dir, "bad.yaml", "{{{{ not yaml at all")

	_, err := LoadProofs(dir)
	assert.Error(t, err)
}

func TestLoadProofs_MissingRequiredFields(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{
			name: "missing vuln class",
			content: `validation_type: time_based
max_requests: 5
max_duration_seconds: 30
`,
		},
		{
			name: "missing validation type",
			content: `vulnerability_class: sqli
max_requests: 5
max_duration_seconds: 30
`,
		},
		{
			name: "zero max requests",
			content: `vulnerability_class: sqli
validation_type: time_based
max_requests: 0
max_duration_seconds: 30
`,
		},
		{
			name: "negative max requests",
			content: `vulnerability_class: sqli
validation_type: time_based
max_requests: -1
max_duration_seconds: 30
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTestProof(t, dir, "bad.yaml", tt.content)

			_, err := LoadProofs(dir)
			assert.Error(t, err)
			assert.True(t, errors.Is(err, ErrProofInvalid))
		})
	}
}

func TestLoadProofs_NonexistentDirectory(t *testing.T) {
	_, err := LoadProofs("/nonexistent/path/that/does/not/exist")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrProofDirNotFound))
}

func TestLoadProofs_SkipsNonYAML(t *testing.T) {
	dir := t.TempDir()
	writeTestProof(t, dir, "sqli_time.yaml", validProofYAML)
	writeTestProof(t, dir, "readme.txt", "this is not a proof")
	writeTestProof(t, dir, "notes.md", "# Notes")

	lib, err := LoadProofs(dir)
	require.NoError(t, err)
	assert.Len(t, lib.List(), 1)
}

func TestList(t *testing.T) {
	dir := t.TempDir()
	writeTestProof(t, dir, "sqli_time.yaml", validProofYAML)
	writeTestProof(t, dir, "sqli_error.yaml", secondProofYAML)
	writeTestProof(t, dir, "xss_reflected.yaml", xssProofYAML)

	lib, err := LoadProofs(dir)
	require.NoError(t, err)

	all := lib.List()
	assert.Len(t, all, 3)

	vulnClasses := make(map[string]bool)
	for _, pb := range all {
		vulnClasses[pb.VulnClass] = true
	}
	assert.True(t, vulnClasses["sqli"])
	assert.True(t, vulnClasses["xss"])
}

func TestLoadProofs_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()

	lib, err := LoadProofs(dir)
	require.NoError(t, err)
	assert.Empty(t, lib.List())
}
