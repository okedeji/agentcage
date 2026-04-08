package assessment

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// allowedConfirmationTypes is the set of confirmation strategies validator
// cages know how to execute. Adding a new type here requires a corresponding
// implementation in the validator cage runtime.
var allowedConfirmationTypes = map[string]struct{}{
	"response_contains":   {},
	"response_time_delta": {},
	"response_status":     {},
	"oob_callback":        {},
}

// allowedHTTPMethods is the set of HTTP verbs accepted in proof payloads.
var allowedHTTPMethods = map[string]struct{}{
	"GET": {}, "POST": {}, "PUT": {}, "PATCH": {}, "DELETE": {}, "HEAD": {}, "OPTIONS": {},
}

// MaxProofDurationSeconds caps how long a single validation run may take.
const MaxProofDurationSeconds = 600

// normalizeVulnClass canonicalizes a vulnerability class string so that
// "SQLi", "sqli", and "  SQLI  " all match the same proof bucket.
func normalizeVulnClass(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

type Proof struct {
	VulnClass      string               `yaml:"vulnerability_class"`
	ValidationType string               `yaml:"validation_type"`
	Description    string               `yaml:"description"`
	Payload        ProofPayload      `yaml:"payload_template"`
	Confirmation   ProofConfirmation `yaml:"confirmation"`
	MaxRequests        int                  `yaml:"max_requests"`
	MaxDurationSeconds int                  `yaml:"max_duration_seconds"`
	Safety             SafetyClassification `yaml:"safety_classification"`
}

type ProofPayload struct {
	Method    string `yaml:"method"`
	URL       string `yaml:"url"`
	Parameter string `yaml:"parameter"`
	Value     string `yaml:"value"`
}

type ProofConfirmation struct {
	Type            string `yaml:"type"`
	ExpectedDeltaMS int    `yaml:"expected_delta_ms"`
	ToleranceMS     int    `yaml:"tolerance_ms"`
	ExpectedPattern string `yaml:"expected_pattern"`
	TimeoutSeconds  int    `yaml:"timeout_seconds"`
}

type SafetyClassification struct {
	Destructive       bool   `yaml:"destructive"`
	DataExfiltration  bool   `yaml:"data_exfiltration"`
	StateModification bool   `yaml:"state_modification"`
	Rationale         string `yaml:"rationale"`
}

var (
	ErrProofNotFound    = errors.New("proof not found")
	ErrProofInvalid     = errors.New("invalid proof")
	ErrProofDirNotFound = errors.New("proof directory not found")
)

type ProofLibrary struct {
	mu     sync.RWMutex
	dir    string
	proofs map[string]map[string]*Proof
}

func LoadProofs(dir string) (*ProofLibrary, error) {
	lib := &ProofLibrary{dir: dir}
	if err := lib.Reload(); err != nil {
		return nil, err
	}
	return lib, nil
}

// Reload re-reads every proof YAML in the library's directory and atomically
// swaps the in-memory index. Used after an operator adds new proofs to
// resolve a proof_gap intervention without restarting the orchestrator.
func (l *ProofLibrary) Reload() error {
	dir := l.dir
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("reading proof directory %s: %w", dir, ErrProofDirNotFound)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory: %w", dir, ErrProofDirNotFound)
	}

	loaded := make(map[string]map[string]*Proof)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("listing proof directory %s: %w", dir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := filepath.Ext(entry.Name())
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		pb, err := loadProof(path)
		if err != nil {
			return fmt.Errorf("loading proof %s: %w", entry.Name(), err)
		}

		if err := validateProof(pb); err != nil {
			return fmt.Errorf("validating proof %s: %w", entry.Name(), err)
		}

		// Normalize on load so all lookups can rely on canonical keys.
		pb.VulnClass = normalizeVulnClass(pb.VulnClass)
		pb.ValidationType = strings.ToLower(strings.TrimSpace(pb.ValidationType))

		if loaded[pb.VulnClass] == nil {
			loaded[pb.VulnClass] = make(map[string]*Proof)
		}
		if _, dup := loaded[pb.VulnClass][pb.ValidationType]; dup {
			return fmt.Errorf("duplicate proof for %s/%s in %s: %w", pb.VulnClass, pb.ValidationType, entry.Name(), ErrProofInvalid)
		}
		loaded[pb.VulnClass][pb.ValidationType] = pb
	}

	l.mu.Lock()
	l.proofs = loaded
	l.mu.Unlock()
	return nil
}

func loadProof(path string) (*Proof, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	var pb Proof
	if err := yaml.Unmarshal(data, &pb); err != nil {
		return nil, fmt.Errorf("parsing YAML: %w", err)
	}

	return &pb, nil
}

func validateProof(pb *Proof) error {
	if normalizeVulnClass(pb.VulnClass) == "" {
		return fmt.Errorf("missing vulnerability_class: %w", ErrProofInvalid)
	}
	if strings.TrimSpace(pb.ValidationType) == "" {
		return fmt.Errorf("missing validation_type: %w", ErrProofInvalid)
	}
	if pb.MaxRequests <= 0 {
		return fmt.Errorf("max_requests must be positive, got %d: %w", pb.MaxRequests, ErrProofInvalid)
	}
	if pb.MaxDurationSeconds <= 0 {
		return fmt.Errorf("max_duration_seconds must be positive, got %d: %w", pb.MaxDurationSeconds, ErrProofInvalid)
	}
	if pb.MaxDurationSeconds > MaxProofDurationSeconds {
		return fmt.Errorf("max_duration_seconds %d exceeds cap %d: %w", pb.MaxDurationSeconds, MaxProofDurationSeconds, ErrProofInvalid)
	}
	if strings.TrimSpace(pb.Confirmation.Type) == "" {
		return fmt.Errorf("missing confirmation.type: %w", ErrProofInvalid)
	}
	if _, ok := allowedConfirmationTypes[pb.Confirmation.Type]; !ok {
		return fmt.Errorf("unknown confirmation.type %q: %w", pb.Confirmation.Type, ErrProofInvalid)
	}
	if pb.Payload.Method != "" {
		if _, ok := allowedHTTPMethods[strings.ToUpper(pb.Payload.Method)]; !ok {
			// Templated methods like "{{ candidate.method }}" are
			// resolved at validation time. Reject only literal bad verbs.
			if !strings.Contains(pb.Payload.Method, "{{") {
				return fmt.Errorf("unknown payload.method %q: %w", pb.Payload.Method, ErrProofInvalid)
			}
		}
	}
	if pb.Confirmation.Type == "response_time_delta" && pb.Confirmation.ExpectedDeltaMS <= 0 {
		return fmt.Errorf("response_time_delta requires positive expected_delta_ms: %w", ErrProofInvalid)
	}
	if pb.Confirmation.Type == "response_contains" && strings.TrimSpace(pb.Confirmation.ExpectedPattern) == "" {
		return fmt.Errorf("response_contains requires expected_pattern: %w", ErrProofInvalid)
	}
	return nil
}

func (l *ProofLibrary) Get(vulnClass, validationType string) (*Proof, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	vc := normalizeVulnClass(vulnClass)
	vt := strings.ToLower(strings.TrimSpace(validationType))
	byType, ok := l.proofs[vc]
	if !ok {
		return nil, fmt.Errorf("vuln class %q: %w", vulnClass, ErrProofNotFound)
	}
	pb, ok := byType[vt]
	if !ok {
		return nil, fmt.Errorf("vuln class %q validation type %q: %w", vulnClass, validationType, ErrProofNotFound)
	}
	return pb, nil
}

// GetByVulnClass returns all proofs for the given vuln class, sorted by
// validation_type for deterministic selection across workflow replays.
func (l *ProofLibrary) GetByVulnClass(vulnClass string) []*Proof {
	l.mu.RLock()
	defer l.mu.RUnlock()
	byType, ok := l.proofs[normalizeVulnClass(vulnClass)]
	if !ok {
		return nil
	}
	result := make([]*Proof, 0, len(byType))
	for _, pb := range byType {
		result = append(result, pb)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].ValidationType < result[j].ValidationType
	})
	return result
}

// List returns every loaded proof, sorted by (vuln_class, validation_type).
func (l *ProofLibrary) List() []*Proof {
	l.mu.RLock()
	defer l.mu.RUnlock()
	var result []*Proof
	for _, byType := range l.proofs {
		for _, pb := range byType {
			result = append(result, pb)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].VulnClass != result[j].VulnClass {
			return result[i].VulnClass < result[j].VulnClass
		}
		return result[i].ValidationType < result[j].ValidationType
	})
	return result
}
