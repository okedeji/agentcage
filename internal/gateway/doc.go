// Package gateway is the LLM gateway client. It proxies chat
// completion requests to a single configured endpoint, retries
// transient failures with exponential backoff, gives up on 4xx, and
// records token usage per cage. The token meter and budget enforcer
// live here too: every request is checked against the cage's budget
// before going out, and exhaustion returns ErrBudgetExhausted instead
// of silently overspending.
//
// Auth failures are tracked across requests so a key rotation that
// triggers a single 401 doesn't fire an alert, but sustained
// failures do.
package gateway
