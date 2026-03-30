package assessment

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Playbook struct {
	VulnClass      string               `yaml:"vulnerability_class"`
	ValidationType string               `yaml:"validation_type"`
	Description    string               `yaml:"description"`
	Payload        PlaybookPayload      `yaml:"payload_template"`
	Confirmation   PlaybookConfirmation `yaml:"confirmation"`
	MaxRequests        int                  `yaml:"max_requests"`
	MaxDurationSeconds int                  `yaml:"max_duration_seconds"`
	Safety             SafetyClassification `yaml:"safety_classification"`
}

type PlaybookPayload struct {
	Method    string `yaml:"method"`
	URL       string `yaml:"url"`
	Parameter string `yaml:"parameter"`
	Value     string `yaml:"value"`
}

type PlaybookConfirmation struct {
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
	ErrPlaybookNotFound    = errors.New("playbook not found")
	ErrPlaybookInvalid     = errors.New("invalid playbook")
	ErrPlaybookDirNotFound = errors.New("playbook directory not found")
)

type PlaybookLibrary struct {
	playbooks map[string]map[string]*Playbook
}

func LoadPlaybooks(dir string) (*PlaybookLibrary, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("reading playbook directory %s: %w", dir, ErrPlaybookDirNotFound)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory: %w", dir, ErrPlaybookDirNotFound)
	}

	lib := &PlaybookLibrary{
		playbooks: make(map[string]map[string]*Playbook),
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("listing playbook directory %s: %w", dir, err)
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
		pb, err := loadPlaybook(path)
		if err != nil {
			return nil, fmt.Errorf("loading playbook %s: %w", entry.Name(), err)
		}

		if err := validatePlaybook(pb); err != nil {
			return nil, fmt.Errorf("validating playbook %s: %w", entry.Name(), err)
		}

		if lib.playbooks[pb.VulnClass] == nil {
			lib.playbooks[pb.VulnClass] = make(map[string]*Playbook)
		}
		lib.playbooks[pb.VulnClass][pb.ValidationType] = pb
	}

	return lib, nil
}

func loadPlaybook(path string) (*Playbook, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	var pb Playbook
	if err := yaml.Unmarshal(data, &pb); err != nil {
		return nil, fmt.Errorf("parsing YAML: %w", err)
	}

	return &pb, nil
}

func validatePlaybook(pb *Playbook) error {
	if pb.VulnClass == "" {
		return fmt.Errorf("missing vulnerability_class: %w", ErrPlaybookInvalid)
	}
	if pb.ValidationType == "" {
		return fmt.Errorf("missing validation_type: %w", ErrPlaybookInvalid)
	}
	if pb.MaxRequests <= 0 {
		return fmt.Errorf("max_requests must be positive, got %d: %w", pb.MaxRequests, ErrPlaybookInvalid)
	}
	return nil
}

func (l *PlaybookLibrary) Get(vulnClass, validationType string) (*Playbook, error) {
	byType, ok := l.playbooks[vulnClass]
	if !ok {
		return nil, fmt.Errorf("vuln class %q: %w", vulnClass, ErrPlaybookNotFound)
	}
	pb, ok := byType[validationType]
	if !ok {
		return nil, fmt.Errorf("vuln class %q validation type %q: %w", vulnClass, validationType, ErrPlaybookNotFound)
	}
	return pb, nil
}

func (l *PlaybookLibrary) GetByVulnClass(vulnClass string) []*Playbook {
	byType, ok := l.playbooks[vulnClass]
	if !ok {
		return nil
	}
	result := make([]*Playbook, 0, len(byType))
	for _, pb := range byType {
		result = append(result, pb)
	}
	return result
}

func (l *PlaybookLibrary) List() []*Playbook {
	var result []*Playbook
	for _, byType := range l.playbooks {
		for _, pb := range byType {
			result = append(result, pb)
		}
	}
	return result
}
