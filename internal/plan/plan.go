package plan

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Plan struct {
	Name          string              `yaml:"name"`
	Agent         string              `yaml:"agent"`
	Target        Target              `yaml:"target"`
	Budget        Budget              `yaml:"budget"`
	Limits        Limits              `yaml:"limits"`
	CageTypes     map[string]CageType `yaml:"cage_types"`
	Payload       PlanPayload         `yaml:"payload"`
	Guidance      Guidance            `yaml:"guidance"`
	Notifications Notifications       `yaml:"notifications"`
	Output        Output              `yaml:"output"`
	Tags          map[string]string   `yaml:"tags"`
	CustomerID    string              `yaml:"customer_id"`
}

type PlanPayload struct {
	ExtraBlock []PlanPattern `yaml:"extra_block"`
	ExtraFlag  []PlanPattern `yaml:"extra_flag"`
}

type PlanPattern struct {
	Pattern string `yaml:"pattern"`
	Reason  string `yaml:"reason"`
}

type Target struct {
	Hosts       []string `yaml:"hosts"`
	Ports       []string `yaml:"ports"`
	Paths       []string `yaml:"paths"`
	SkipPaths   []string `yaml:"skip_paths"`
	Credentials string   `yaml:"credentials,omitempty"`
}

type Budget struct {
	Tokens      int64  `yaml:"tokens"`
	MaxDuration string `yaml:"max_duration"`
}

type Limits struct {
	MaxChainDepth      int32 `yaml:"max_chain_depth"`
	MaxConcurrentCages int32 `yaml:"max_concurrent_cages"`
	MaxIterations      int32 `yaml:"max_iterations"`
}

type CageType struct {
	VCPUs         int32  `yaml:"vcpus"`
	MemoryMB      int32  `yaml:"memory_mb"`
	MaxConcurrent int32  `yaml:"max_concurrent"`
	MaxDuration   string `yaml:"max_duration"`
}

type Guidance struct {
	AttackSurface AttackSurface `yaml:"attack_surface"`
	Priorities    Priorities    `yaml:"priorities"`
	Strategy      Strategy      `yaml:"strategy"`
	Validation    Validation    `yaml:"validation"`
}

type AttackSurface struct {
	Endpoints     []string `yaml:"endpoints"`
	APISpecs      []string `yaml:"api_specs"`
	LimitToListed *bool    `yaml:"limit_to_listed,omitempty"`
}

type Priorities struct {
	VulnClasses []string `yaml:"vuln_classes"`
	SkipPaths   []string `yaml:"skip_paths"`
}

type Strategy struct {
	Context         string   `yaml:"context"`
	KnownWeaknesses []string `yaml:"known_weaknesses"`
}

type Validation struct {
	RequirePoC         *bool `yaml:"require_poc,omitempty"`
	HeadlessBrowserXSS *bool `yaml:"headless_browser_xss,omitempty"`
}

type Notifications struct {
	Webhook    string `yaml:"webhook"`
	OnFinding  *bool  `yaml:"on_finding,omitempty"`
	OnComplete *bool  `yaml:"on_complete,omitempty"`
}

type Output struct {
	Format string `yaml:"format"`
	Follow *bool  `yaml:"follow,omitempty"`
}

func Load(path string) (*Plan, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading plan file %s: %w", path, err)
	}
	var p Plan
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing plan file %s: %w", path, err)
	}
	return &p, nil
}

// --require-poc=false can override a plan that has require_poc: true.
func Merge(base, override *Plan) *Plan {
	out := *base

	if override.Name != "" {
		out.Name = override.Name
	}
	if override.Agent != "" {
		out.Agent = override.Agent
	}
	if override.CustomerID != "" {
		out.CustomerID = override.CustomerID
	}

	if len(override.Target.Hosts) > 0 {
		out.Target.Hosts = override.Target.Hosts
	}
	if len(override.Target.Ports) > 0 {
		out.Target.Ports = override.Target.Ports
	}
	if len(override.Target.Paths) > 0 {
		out.Target.Paths = override.Target.Paths
	}
	if len(override.Target.SkipPaths) > 0 {
		out.Target.SkipPaths = override.Target.SkipPaths
	}
	if override.Target.Credentials != "" {
		out.Target.Credentials = override.Target.Credentials
	}

	if override.Budget.Tokens > 0 {
		out.Budget.Tokens = override.Budget.Tokens
	}
	if override.Budget.MaxDuration != "" {
		out.Budget.MaxDuration = override.Budget.MaxDuration
	}

	if override.Limits.MaxChainDepth > 0 {
		out.Limits.MaxChainDepth = override.Limits.MaxChainDepth
	}
	if override.Limits.MaxConcurrentCages > 0 {
		out.Limits.MaxConcurrentCages = override.Limits.MaxConcurrentCages
	}
	if override.Limits.MaxIterations > 0 {
		out.Limits.MaxIterations = override.Limits.MaxIterations
	}
	if len(override.CageTypes) > 0 {
		if out.CageTypes == nil {
			out.CageTypes = make(map[string]CageType)
		}
		for k, v := range override.CageTypes {
			out.CageTypes[k] = v
		}
	}

	if len(override.Guidance.AttackSurface.Endpoints) > 0 {
		out.Guidance.AttackSurface.Endpoints = override.Guidance.AttackSurface.Endpoints
	}
	if len(override.Guidance.AttackSurface.APISpecs) > 0 {
		out.Guidance.AttackSurface.APISpecs = override.Guidance.AttackSurface.APISpecs
	}
	if override.Guidance.AttackSurface.LimitToListed != nil {
		out.Guidance.AttackSurface.LimitToListed = override.Guidance.AttackSurface.LimitToListed
	}
	if len(override.Guidance.Priorities.VulnClasses) > 0 {
		out.Guidance.Priorities.VulnClasses = override.Guidance.Priorities.VulnClasses
	}
	if len(override.Guidance.Priorities.SkipPaths) > 0 {
		out.Guidance.Priorities.SkipPaths = override.Guidance.Priorities.SkipPaths
	}
	if override.Guidance.Strategy.Context != "" {
		out.Guidance.Strategy.Context = override.Guidance.Strategy.Context
	}
	if len(override.Guidance.Strategy.KnownWeaknesses) > 0 {
		out.Guidance.Strategy.KnownWeaknesses = override.Guidance.Strategy.KnownWeaknesses
	}
	if override.Guidance.Validation.RequirePoC != nil {
		out.Guidance.Validation.RequirePoC = override.Guidance.Validation.RequirePoC
	}
	if override.Guidance.Validation.HeadlessBrowserXSS != nil {
		out.Guidance.Validation.HeadlessBrowserXSS = override.Guidance.Validation.HeadlessBrowserXSS
	}

	if override.Notifications.Webhook != "" {
		out.Notifications.Webhook = override.Notifications.Webhook
	}
	if override.Notifications.OnFinding != nil {
		out.Notifications.OnFinding = override.Notifications.OnFinding
	}
	if override.Notifications.OnComplete != nil {
		out.Notifications.OnComplete = override.Notifications.OnComplete
	}

	if override.Output.Format != "" {
		out.Output.Format = override.Output.Format
	}
	if override.Output.Follow != nil {
		out.Output.Follow = override.Output.Follow
	}

	if len(override.Payload.ExtraBlock) > 0 {
		out.Payload.ExtraBlock = override.Payload.ExtraBlock
	}
	if len(override.Payload.ExtraFlag) > 0 {
		out.Payload.ExtraFlag = override.Payload.ExtraFlag
	}

	if len(override.Tags) > 0 {
		out.Tags = override.Tags
	}

	return &out
}

// Call before Validate so validation sees the complete plan.
func ApplyDefaults(p *Plan) {
	if p.Output.Format == "" {
		p.Output.Format = "text"
	}
}

func Validate(p *Plan) error {
	if p.Agent == "" {
		return fmt.Errorf("agent is required (--agent or agent: in plan file)")
	}
	if len(p.Target.Hosts) == 0 {
		return fmt.Errorf("at least one target host is required (--target or target.hosts: in plan file)")
	}
	for _, h := range p.Target.Hosts {
		if h == "" {
			return fmt.Errorf("target host cannot be empty")
		}
	}
	if p.Budget.Tokens < 0 {
		return fmt.Errorf("budget.tokens must not be negative")
	}
	if p.Budget.MaxDuration != "" {
		if _, err := time.ParseDuration(p.Budget.MaxDuration); err != nil {
			return fmt.Errorf("invalid max_duration %q: %w", p.Budget.MaxDuration, err)
		}
	}
	for _, port := range p.Target.Ports {
		if port == "" {
			return fmt.Errorf("target port cannot be empty")
		}
	}
	if p.Limits.MaxChainDepth < 0 {
		return fmt.Errorf("max_chain_depth must not be negative")
	}
	if p.Limits.MaxConcurrentCages < 0 {
		return fmt.Errorf("max_concurrent_cages must not be negative")
	}
	if p.Notifications.Webhook != "" && !strings.HasPrefix(p.Notifications.Webhook, "http") {
		return fmt.Errorf("notifications.webhook must be an HTTP(S) URL")
	}
	for name, ct := range p.CageTypes {
		switch name {
		case "discovery", "validator", "escalation":
		default:
			return fmt.Errorf("unknown cage type %q in cage_types (supported: discovery, validator, escalation)", name)
		}
		if ct.MaxDuration != "" {
			if _, err := time.ParseDuration(ct.MaxDuration); err != nil {
				return fmt.Errorf("cage_types.%s.max_duration %q: %w", name, ct.MaxDuration, err)
			}
		}
	}
	switch p.Output.Format {
	case "text", "json", "":
	default:
		return fmt.Errorf("unknown output.format %q (supported: text, json)", p.Output.Format)
	}
	return nil
}

type RawFlags struct {
	Agent            string
	Target           string
	Ports            []string
	Paths            []string
	SkipPaths        []string
	TokenBudget      int64
	MaxDuration      string
	MaxChainDepth    int
	MaxConcurrent    int
	MaxIterations    int
	Context          string
	Focus            []string
	Skip             []string
	Endpoints        []string
	APISpecs         []string
	KnownWeaknesses  []string
	RequirePoC       bool
	HeadlessXSS      bool
	Notify           string
	NotifyOnFinding  bool
	NotifyOnComplete bool
	Follow           bool
	Format           string
	Name             string
	Tags             []string
	CustomerID       string
}

func FlagsToOverride(explicit map[string]bool, f RawFlags) *Plan {
	p := &Plan{}

	if explicit["agent"] {
		p.Agent = f.Agent
	}
	if explicit["target"] {
		p.Target.Hosts = splitAndTrim(f.Target, ",")
	}
	if explicit["port"] {
		p.Target.Ports = f.Ports
	}
	if explicit["path"] {
		p.Target.Paths = f.Paths
	}
	if explicit["skip-path"] {
		p.Target.SkipPaths = f.SkipPaths
	}
	if explicit["token-budget"] {
		p.Budget.Tokens = f.TokenBudget
	}
	if explicit["max-duration"] {
		p.Budget.MaxDuration = f.MaxDuration
	}
	if explicit["max-chain-depth"] {
		p.Limits.MaxChainDepth = int32(f.MaxChainDepth)
	}
	if explicit["max-concurrent"] {
		p.Limits.MaxConcurrentCages = int32(f.MaxConcurrent)
	}
	if explicit["max-iterations"] {
		p.Limits.MaxIterations = int32(f.MaxIterations)
	}
	if explicit["context"] {
		p.Guidance.Strategy.Context = f.Context
	}
	if explicit["focus"] {
		p.Guidance.Priorities.VulnClasses = f.Focus
	}
	if explicit["skip"] {
		p.Guidance.Priorities.SkipPaths = f.Skip
	}
	if explicit["endpoint"] {
		p.Guidance.AttackSurface.Endpoints = f.Endpoints
	}
	if explicit["api-spec"] {
		p.Guidance.AttackSurface.APISpecs = f.APISpecs
	}
	if explicit["known-weakness"] {
		p.Guidance.Strategy.KnownWeaknesses = f.KnownWeaknesses
	}
	if explicit["require-poc"] {
		p.Guidance.Validation.RequirePoC = boolPtr(f.RequirePoC)
	}
	if explicit["headless-xss"] {
		p.Guidance.Validation.HeadlessBrowserXSS = boolPtr(f.HeadlessXSS)
	}
	if explicit["notify"] {
		p.Notifications.Webhook = f.Notify
	}
	if explicit["notify-on-finding"] {
		p.Notifications.OnFinding = boolPtr(f.NotifyOnFinding)
	}
	if explicit["notify-on-complete"] {
		p.Notifications.OnComplete = boolPtr(f.NotifyOnComplete)
	}
	if explicit["follow"] {
		p.Output.Follow = boolPtr(f.Follow)
	}
	if explicit["format"] {
		p.Output.Format = f.Format
	}
	if explicit["name"] {
		p.Name = f.Name
	}
	if explicit["tag"] {
		p.Tags = ParseTags(f.Tags)
	}
	if explicit["customer-id"] {
		p.CustomerID = f.CustomerID
	}

	return p
}

func boolPtr(v bool) *bool { return &v }

// BoolVal returns the value of a *bool, defaulting to false if nil.
func BoolVal(b *bool) bool {
	if b == nil {
		return false
	}
	return *b
}

func splitAndTrim(s, sep string) []string {
	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func ParseTags(tags []string) map[string]string {
	m := make(map[string]string, len(tags))
	for _, t := range tags {
		k, v, ok := strings.Cut(t, "=")
		if ok {
			m[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return m
}
