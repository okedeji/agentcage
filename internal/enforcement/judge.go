package enforcement

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type JudgeRequest struct {
	Payloads []JudgePayload `json:"payloads"`
}

type JudgePayload struct {
	CageType     string `json:"cage_type"`
	VulnClass    string `json:"vuln_class"`
	AssessmentID string `json:"assessment_id"`
	Method       string `json:"method"`
	URL          string `json:"url"`
	Body         string `json:"body"`
}

type JudgeResponse struct {
	Results []JudgeResult `json:"results"`
}

type JudgeResult struct {
	Safe       bool    `json:"safe"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
}

type JudgeClient struct {
	endpoint            string
	confidenceThreshold float64
	apiKey              string
	httpClient          *http.Client
}

func NewJudgeClient(endpoint string, confidenceThreshold float64, apiKey string, timeout time.Duration) *JudgeClient {
	return &JudgeClient{
		endpoint:            endpoint,
		confidenceThreshold: confidenceThreshold,
		apiKey:              apiKey,
		httpClient:          &http.Client{Timeout: timeout},
	}
}

// Evaluate sends a single payload to the judge endpoint and returns a
// decision. Uses its own timeout rather than the caller's context so the
// agent's request deadline cannot cut the judge call short.
func (c *JudgeClient) Evaluate(cageType, vulnClass, assessmentID, method, url string, body []byte) (PayloadDecision, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.httpClient.Timeout)
	defer cancel()

	reqBody := JudgeRequest{
		Payloads: []JudgePayload{{
			CageType:     cageType,
			VulnClass:    vulnClass,
			AssessmentID: assessmentID,
			Method:       method,
			URL:          url,
			Body:         string(body),
		}},
	}

	payload, err := json.Marshal(reqBody)
	if err != nil {
		return PayloadBlock, "judge request marshal failed", fmt.Errorf("marshaling judge request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(payload))
	if err != nil {
		return PayloadBlock, "judge request creation failed", fmt.Errorf("creating judge request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return PayloadBlock, "judge unreachable", fmt.Errorf("calling judge endpoint: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		return PayloadBlock, fmt.Sprintf("judge returned status %d", resp.StatusCode), fmt.Errorf("judge endpoint returned %d", resp.StatusCode)
	}

	var judgeResp JudgeResponse
	if err := json.NewDecoder(resp.Body).Decode(&judgeResp); err != nil {
		return PayloadBlock, "judge response malformed", fmt.Errorf("decoding judge response: %w", err)
	}

	if len(judgeResp.Results) != 1 {
		return PayloadBlock, "judge returned wrong result count", fmt.Errorf("expected 1 result, got %d", len(judgeResp.Results))
	}

	result := judgeResp.Results[0]
	if result.Confidence < 0 || result.Confidence > 1 {
		return PayloadBlock, "judge returned invalid confidence", fmt.Errorf("confidence %f out of [0,1] range", result.Confidence)
	}

	if result.Confidence < c.confidenceThreshold {
		return PayloadHold, result.Reason, nil
	}

	if result.Safe {
		return PayloadAllow, result.Reason, nil
	}
	return PayloadBlock, result.Reason, nil
}
