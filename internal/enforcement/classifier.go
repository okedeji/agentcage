package enforcement

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

type ClassificationRequest struct {
	Payloads []ClassificationPayload `json:"payloads"`
}

type ClassificationPayload struct {
	VulnClass string `json:"vuln_class"`
	Method    string `json:"method"`
	URL       string `json:"url"`
	Body      string `json:"body"`
}

type ClassificationResponse struct {
	Results []ClassificationResult `json:"results"`
}

type ClassificationResult struct {
	Safe       bool    `json:"safe"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
}

var ErrNoClassificationData = errors.New("classification response missing results")
var ErrResultCountMismatch = errors.New("classification results count does not match payloads")

type ClassificationClient struct {
	endpoint   string
	httpClient *http.Client
	timeout    time.Duration
}

func NewClassificationClient(endpoint string, timeout time.Duration) *ClassificationClient {
	return &ClassificationClient{
		endpoint:   endpoint,
		httpClient: &http.Client{},
		timeout:    timeout,
	}
}

func (c *ClassificationClient) Classify(ctx context.Context, payloads []ClassificationPayload) ([]ClassificationResult, error) {
	reqBody, err := json.Marshal(ClassificationRequest{Payloads: payloads})
	if err != nil {
		return nil, fmt.Errorf("marshaling classification request: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("creating classification request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending classification request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading classification response: %w", err)
	}

	var classResp ClassificationResponse
	if err := json.Unmarshal(body, &classResp); err != nil {
		return nil, fmt.Errorf("unmarshaling classification response: %w", err)
	}

	if classResp.Results == nil {
		return nil, ErrNoClassificationData
	}

	if len(classResp.Results) != len(payloads) {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrResultCountMismatch, len(classResp.Results), len(payloads))
	}

	return classResp.Results, nil
}
