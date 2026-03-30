package enforcement

import (
	"fmt"
	"regexp"
)

type ProxyEngine struct {
	vulnClass string
	patterns  []*compiledPattern
}

type compiledPattern struct {
	regex   *regexp.Regexp
	message string
}

func NewProxyEngine(vulnClass string, patterns map[string]string) (*ProxyEngine, error) {
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
	return &ProxyEngine{
		vulnClass: vulnClass,
		patterns:  compiled,
	}, nil
}

func (e *ProxyEngine) Inspect(method, url string, body []byte) (PayloadDecision, string) {
	content := string(body)
	for _, p := range e.patterns {
		if p.regex.MatchString(content) {
			return PayloadBlock, p.message
		}
		if p.regex.MatchString(url) {
			return PayloadBlock, p.message
		}
	}
	return PayloadAllow, ""
}

