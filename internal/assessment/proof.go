package assessment

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

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
	proofs map[string]map[string]*Proof
}

func LoadProofs(dir string) (*ProofLibrary, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("reading proof directory %s: %w", dir, ErrProofDirNotFound)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory: %w", dir, ErrProofDirNotFound)
	}

	lib := &ProofLibrary{
		proofs: make(map[string]map[string]*Proof),
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("listing proof directory %s: %w", dir, err)
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
			return nil, fmt.Errorf("loading proof %s: %w", entry.Name(), err)
		}

		if err := validateProof(pb); err != nil {
			return nil, fmt.Errorf("validating proof %s: %w", entry.Name(), err)
		}

		if lib.proofs[pb.VulnClass] == nil {
			lib.proofs[pb.VulnClass] = make(map[string]*Proof)
		}
		lib.proofs[pb.VulnClass][pb.ValidationType] = pb
	}

	return lib, nil
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
	if pb.VulnClass == "" {
		return fmt.Errorf("missing vulnerability_class: %w", ErrProofInvalid)
	}
	if pb.ValidationType == "" {
		return fmt.Errorf("missing validation_type: %w", ErrProofInvalid)
	}
	if pb.MaxRequests <= 0 {
		return fmt.Errorf("max_requests must be positive, got %d: %w", pb.MaxRequests, ErrProofInvalid)
	}
	return nil
}

func (l *ProofLibrary) Get(vulnClass, validationType string) (*Proof, error) {
	byType, ok := l.proofs[vulnClass]
	if !ok {
		return nil, fmt.Errorf("vuln class %q: %w", vulnClass, ErrProofNotFound)
	}
	pb, ok := byType[validationType]
	if !ok {
		return nil, fmt.Errorf("vuln class %q validation type %q: %w", vulnClass, validationType, ErrProofNotFound)
	}
	return pb, nil
}

func (l *ProofLibrary) GetByVulnClass(vulnClass string) []*Proof {
	byType, ok := l.proofs[vulnClass]
	if !ok {
		return nil
	}
	result := make([]*Proof, 0, len(byType))
	for _, pb := range byType {
		result = append(result, pb)
	}
	return result
}

func (l *ProofLibrary) List() []*Proof {
	var result []*Proof
	for _, byType := range l.proofs {
		for _, pb := range byType {
			result = append(result, pb)
		}
	}
	return result
}
