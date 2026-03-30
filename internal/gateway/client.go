package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Client struct {
	endpoint   string
	httpClient *http.Client
	meter      *TokenMeter
	budget     *BudgetEnforcer
	timeout    time.Duration
}

func NewClient(endpoint string, timeout time.Duration, meter *TokenMeter, budget *BudgetEnforcer) *Client {
	return &Client{
		endpoint:   endpoint,
		httpClient: &http.Client{},
		meter:      meter,
		budget:     budget,
		timeout:    timeout,
	}
}

func (c *Client) ChatCompletion(ctx context.Context, cageID string, tokenBudget int64, req LLMRequest) (*LLMResponse, error) {
	if err := c.budget.Check(cageID, tokenBudget); err != nil {
		return nil, fmt.Errorf("checking budget for cage %s: %w", cageID, err)
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshaling LLM request: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("sending request to LLM gateway: %w", err)
	}
	defer httpResp.Body.Close()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading LLM gateway response: %w", err)
	}

	var resp LLMResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("unmarshaling LLM response: %w", err)
	}

	if resp.Usage.TotalTokens == 0 {
		return nil, ErrNoUsageData
	}

	c.meter.Record(cageID, resp.Model, resp.Usage.PromptTokens, resp.Usage.CompletionTokens)

	return &resp, nil
}
