package enforcement

import (
	"fmt"
	"regexp"
)

// ProxyEngine inspects outbound payloads against compiled regex patterns.
// Block patterns reject the request. Flag patterns (used in flag
// mode) return PayloadHold so the proxy can pause the request and ask a
// human. Block patterns are always checked first.
type ProxyEngine struct {
	vulnClass        string
	blockPatterns    []*compiledPattern
	flagPatterns []*compiledPattern
}

type compiledPattern struct {
	regex   *regexp.Regexp
	message string
}

func compilePatterns(vulnClass string, patterns map[string]string) ([]*compiledPattern, error) {
	compiled := make([]*compiledPattern, 0, len(patterns))
	for pattern, message := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("compiling pattern %q for vuln class %s: %w", pattern, vulnClass, err)
		}
		compiled = append(compiled, &compiledPattern{
			regex:   re,
			message: message,
		})
	}
	return compiled, nil
}

// NewProxyEngine compiles block patterns and optional flag patterns.
// Flag patterns are only checked when non-nil; they return PayloadHold
// for requests that are ambiguous enough to need human review.
func NewProxyEngine(vulnClass string, blockPatterns map[string]string, flagPatterns map[string]string) (*ProxyEngine, error) {
	block, err := compilePatterns(vulnClass, blockPatterns)
	if err != nil {
		return nil, err
	}
	var flag []*compiledPattern
	if len(flagPatterns) > 0 {
		flag, err = compilePatterns(vulnClass, flagPatterns)
		if err != nil {
			return nil, err
		}
	}
	return &ProxyEngine{
		vulnClass:        vulnClass,
		blockPatterns:    block,
		flagPatterns: flag,
	}, nil
}

// Inspect checks a request against block patterns first, then flag
// patterns. Returns PayloadBlock, PayloadHold, or PayloadAllow.
func (e *ProxyEngine) Inspect(method, url string, body []byte) (PayloadDecision, string) {
	content := string(body)
	for _, p := range e.blockPatterns {
		if p.regex.MatchString(content) || p.regex.MatchString(url) {
			return PayloadBlock, p.message
		}
	}
	for _, p := range e.flagPatterns {
		if p.regex.MatchString(content) || p.regex.MatchString(url) {
			return PayloadHold, p.message
		}
	}
	return PayloadAllow, ""
}
