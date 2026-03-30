package enforcement

import (
	"context"
	"fmt"
	"regexp"
)

type ProxyEngine struct {
	vulnClass   string
	patterns    []*compiledPattern
	batcher     *PayloadBatcher
	threshold   float64
	onUncertain PayloadDecision
}

type compiledPattern struct {
	regex   *regexp.Regexp
	message string
}

type ProxyClassifyConfig struct {
	Batcher     *PayloadBatcher
	Threshold   float64
	OnUncertain PayloadDecision
}

func NewProxyEngine(vulnClass string, patterns map[string]string, classify *ProxyClassifyConfig) (*ProxyEngine, error) {
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

	e := &ProxyEngine{
		vulnClass: vulnClass,
		patterns:  compiled,
	}

	if classify != nil {
		e.batcher = classify.Batcher
		e.threshold = classify.Threshold
		e.onUncertain = classify.OnUncertain
	}

	return e, nil
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

func (e *ProxyEngine) InspectWithClassification(ctx context.Context, method, url string, body []byte) (PayloadDecision, string, error) {
	decision, reason := e.Inspect(method, url, body)
	if decision == PayloadBlock {
		return PayloadBlock, reason, nil
	}

	if e.batcher == nil {
		return PayloadAllow, "", nil
	}

	resultCh := e.batcher.Submit(ClassificationPayload{
		VulnClass: e.vulnClass,
		Method:    method,
		URL:       url,
		Body:      string(body),
	})

	select {
	case result := <-resultCh:
		if result.Confidence >= e.threshold {
			return PayloadAllow, "", nil
		}
		return e.onUncertain, result.Reason, nil
	case <-ctx.Done():
		return PayloadBlock, "classification timeout", ctx.Err()
	}
}
