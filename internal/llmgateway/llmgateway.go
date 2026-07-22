// Package llmgateway proxies an agent's OpenAI-compatible calls to the
// configured provider endpoint, holds provider keys so agents never see one,
// meters per-call cost, and enforces the run's shared budget.
package llmgateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SpendLogPrefix marks a spend snapshot line in the gateway's stdout. No
// graceful shutdown: the cumulative total is logged after every metered call
// and the runtime reads the last line at teardown.
const SpendLogPrefix = "VESSEL_SPEND "

// WriteSpendLine emits one snapshot as a prefixed JSON line.
func WriteSpendLine(w io.Writer, r SpendReport) {
	b, err := json.Marshal(r)
	if err != nil {
		return
	}
	_, _ = fmt.Fprintln(w, SpendLogPrefix+string(b))
}

// ParseSpendLine returns the last snapshot in the gateway's log output. found
// is false when no metered call was ever logged.
func ParseSpendLine(logs string) (report SpendReport, found bool) {
	for _, line := range strings.Split(logs, "\n") {
		s, ok := strings.CutPrefix(strings.TrimSpace(line), SpendLogPrefix)
		if !ok {
			continue
		}
		var r SpendReport
		if json.Unmarshal([]byte(s), &r) == nil {
			report, found = r, true
		}
	}
	return report, found
}

// CallEvent is one metered LLM call, logged to the gateway's stdout for the
// daemon to assemble into the run's trace. Times are gateway-clock unix nanos:
// durations are exact, alignment with the daemon's clock is not.
type CallEvent struct {
	Agent            string `json:"agent"`
	Model            string `json:"model"`
	PromptTokens     int64  `json:"prompt_tokens"`
	CompletionTokens int64  `json:"completion_tokens"`
	CostMicroUSD     int64  `json:"cost_micro_usd"`
	StartUnixNano    int64  `json:"start_unix_nano"`
	EndUnixNano      int64  `json:"end_unix_nano"`
}

// CallLogPrefix marks a per-call event line in the gateway's stdout.
const CallLogPrefix = "VESSEL_CALL "

// WriteCallLine emits one call event as a prefixed JSON line.
func WriteCallLine(w io.Writer, e CallEvent) {
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	_, _ = fmt.Fprintln(w, CallLogPrefix+string(b))
}

// ParseCallLines returns every call event in the gateway's log output, in order.
func ParseCallLines(logs string) []CallEvent {
	var out []CallEvent
	for _, line := range strings.Split(logs, "\n") {
		s, ok := strings.CutPrefix(strings.TrimSpace(line), CallLogPrefix)
		if !ok {
			continue
		}
		var e CallEvent
		if json.Unmarshal([]byte(s), &e) == nil {
			out = append(out, e)
		}
	}
	return out
}

// CallRecord is a metered call's full payload, logged only when recording for
// replay. Request is captured before the proxy attaches the provider key, so
// no key ever reaches a replay artifact.
type CallRecord struct {
	Agent            string `json:"agent"`
	Model            string `json:"model"`
	Request          []byte `json:"request,omitempty"`
	Response         []byte `json:"response,omitempty"`
	PromptTokens     int64  `json:"prompt_tokens"`
	CompletionTokens int64  `json:"completion_tokens"`
	CostMicroUSD     int64  `json:"cost_micro_usd"`
	StartUnixNano    int64  `json:"start_unix_nano"`
	Streamed         bool   `json:"streamed,omitempty"`
}

// ReplayLogPrefix marks a full-payload call record, written only when recording.
const ReplayLogPrefix = "VESSEL_REPLAY "

// WriteReplayLine emits one call record as a prefixed JSON line; []byte bodies
// marshal as base64, keeping bodies with newlines on one line.
func WriteReplayLine(w io.Writer, r CallRecord) {
	b, err := json.Marshal(r)
	if err != nil {
		return
	}
	_, _ = fmt.Fprintln(w, ReplayLogPrefix+string(b))
}

// ParseReplayLines returns every call record in the gateway's log output, in order.
func ParseReplayLines(logs string) []CallRecord {
	var out []CallRecord
	for _, line := range strings.Split(logs, "\n") {
		s, ok := strings.CutPrefix(strings.TrimSpace(line), ReplayLogPrefix)
		if !ok {
			continue
		}
		var r CallRecord
		if json.Unmarshal([]byte(s), &r) == nil {
			out = append(out, r)
		}
	}
	return out
}

// Secret is a provider key: redacted by %v/%s/%#v, but marshals to its real
// value because the Config JSON is the transport into the gateway container.
type Secret string

func (s Secret) String() string   { return "[redacted]" }
func (s Secret) GoString() string { return "[redacted]" }

// Endpoint is one operator-configured OpenAI-compatible provider. Model is
// substituted on fallback; PriceIn/PriceOut are micro-USD per million tokens.
type Endpoint struct {
	BaseURL  string `json:"base_url"`
	Key      Secret `json:"key,omitempty"`
	Model    string `json:"model,omitempty"`
	PriceIn  int64  `json:"price_in,omitempty"`
	PriceOut int64  `json:"price_out,omitempty"`
}

// Config is the runtime-injected gateway configuration. Agents is keyed by
// capability token; a zero budget is unbounded.
type Config struct {
	Endpoints      map[string]Endpoint   `json:"endpoints"`
	Default        string                `json:"default"`
	Agents         map[string]AgentRoute `json:"agents"`
	BudgetMicroUSD int64                 `json:"budget_micro_usd,omitempty"`
	// Record enables full-payload capture for replay; heavy, so off by default.
	Record bool `json:"record,omitempty"`
	// MaxBodyBytes overrides the forwarded-request-body cap. Zero means the
	// default; the runtime resolves VESSEL_MAX_LLM_BODY on the host and sets it
	// here, since the gateway runs in a container without config access.
	MaxBodyBytes int64 `json:"max_body_bytes,omitempty"`
}

// AgentRoute is one reasoning agent's LLM route, addressed by the capability
// token (the map key) injected only into that agent's URL: a sibling cannot
// forge another agent's path to use its model or misattribute spend. Key is
// the real agent key, kept for the spend tally.
type AgentRoute struct {
	Key   string `json:"key"`
	Model string `json:"model"`
}

// SpendReport is the cumulative spend snapshot emitted after each metered call.
type SpendReport struct {
	TotalMicroUSD  int64                 `json:"total_micro_usd"`
	BudgetMicroUSD int64                 `json:"budget_micro_usd"`
	Agents         map[string]AgentSpend `json:"agents"`
}

// AgentSpend is one agent's slice of the shared budget.
type AgentSpend struct {
	SpentMicroUSD int64 `json:"spent_micro_usd"`
	Calls         int64 `json:"calls"`
}

// route is an agent's endpoint and model, resolved once at boot.
type route struct {
	proxy *httputil.ReverseProxy
	model string
	ep    Endpoint
}

// defaultMaxTokens bounds the completion estimate when a request omits
// max_tokens, so a call with no declared ceiling still reserves a
// non-trivial amount against the budget rather than reserving ~0.
const defaultMaxTokens = 4096

// maxEstimateTokens caps the completion count used for the reservation
// estimate. max_tokens is cage-controlled, so without a ceiling a call could
// declare max_tokens=1e15 and reserve more than the whole budget, starving
// every sibling agent (and overflowing int64 in the price multiply). No real
// model serves anywhere near this many completion tokens.
const maxEstimateTokens = 1 << 20

// defaultMaxLLMRequestBytes caps a forwarded request body so a cage cannot OOM
// the gateway with a giant body; large contexts still fit comfortably.
// Config.MaxBodyBytes (from VESSEL_MAX_LLM_BODY on the host) overrides it.
const defaultMaxLLMRequestBytes = 8 << 20

// reservationKey carries a call's reserved estimate to the response side so it
// is released (and reconciled) exactly once on completion.
type reservationKey struct{}

func reservation(ctx context.Context) int64 {
	if est, ok := ctx.Value(reservationKey{}).(int64); ok {
		return est
	}
	return 0
}

// allowedLLMPath restricts the forwarded upstream path (after the cage's token
// segment) to the OpenAI-compatible inference endpoints. Everything else under
// the provider base URL (files, batches, fine-tuning, assistants) is refused so
// the operator's key cannot be driven off the metered inference path.
func allowedLLMPath(p string) bool {
	switch strings.TrimSuffix(p, "/") {
	case "/chat/completions", "/completions", "/embeddings", "/responses":
		return true
	}
	return false
}

// estimateCost is the upper-bound cost charged at admission (reservation) and,
// if a response never yields a usage block, as the settled fallback. Prompt
// size is approximated from the request bytes (~4 bytes/token) and the
// completion from the request's max_tokens (or a default). It never
// under-estimates to zero, so aborting or omitting usage is never cheaper than
// completing honestly.
func estimateCost(ep Endpoint, body []byte) int64 {
	promptTokens := int64(len(body)) / 4
	maxTok := int64(defaultMaxTokens)
	var req struct {
		MaxTokens           *int64 `json:"max_tokens"`
		MaxCompletionTokens *int64 `json:"max_completion_tokens"`
	}
	if json.Unmarshal(body, &req) == nil {
		if req.MaxCompletionTokens != nil && *req.MaxCompletionTokens > 0 {
			maxTok = *req.MaxCompletionTokens
		} else if req.MaxTokens != nil && *req.MaxTokens > 0 {
			maxTok = *req.MaxTokens
		}
	}
	// Clamp the cage-controlled completion count before the price multiply, so
	// a call cannot reserve more than a real completion could cost (starving
	// siblings) or overflow int64.
	if maxTok > maxEstimateTokens {
		maxTok = maxEstimateTokens
	}
	est := ceilDiv(promptTokens*ep.PriceIn, 1_000_000) + ceilDiv(maxTok*ep.PriceOut, 1_000_000)
	if est < 1 {
		est = 1
	}
	return est
}

// Gateway serves the agent-facing proxy and the operator control surface.
type Gateway struct {
	meter *meter
	agent http.Handler
}

// Hooks are the gateway's observation callbacks: cumulative spend after each
// metered call, that call's event, and (only when recording) its full
// payload. All optional; the cmd wires them to stdout.
type Hooks struct {
	Spend   func(SpendReport)
	Call    func(CallEvent)
	Payload func(CallRecord)
}

// New resolves each agent to an endpoint and model once and builds the gateway.
func New(cfg Config, hooks Hooks) *Gateway {
	m := &meter{
		budget:        cfg.BudgetMicroUSD,
		agents:        map[string]int64{},
		calls:         map[string]int64{},
		report:        hooks.Spend,
		recordCall:    hooks.Call,
		recordPayload: hooks.Payload,
		record:        cfg.Record,
		maxBody:       cfg.MaxBodyBytes,
	}
	if m.maxBody <= 0 {
		m.maxBody = defaultMaxLLMRequestBytes
	}
	// Keyed by the capability token a caller addresses, but metered by the real
	// agent key, so the spend tally still attributes to the agent and a forged
	// path cannot be guessed.
	routes := make(map[string]route, len(cfg.Agents))
	for token, ar := range cfg.Agents {
		provider, model := splitModel(ar.Model)
		ep, matched := cfg.Endpoints[provider]
		if !matched {
			ep = cfg.Endpoints[cfg.Default]
			if ep.Model != "" {
				// Fallback: the agent's model is for another provider, so send
				// the model this endpoint actually serves.
				model = ep.Model
			}
		}
		routes[token] = route{proxy: newProxy(ep, m, ar.Key, model), model: model, ep: ep}
	}

	agent := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rt, ok := routes[firstSegment(r.URL.Path)]
		if !ok {
			writeError(w, http.StatusNotFound, "no LLM route for this agent")
			return
		}
		// The cage controls the path after its token; without this it could
		// steer the operator's key at any endpoint under the provider base URL
		// (files, batches, fine-tuning), all off the metered inference path.
		// Restrict to POST and the OpenAI-compatible inference endpoints.
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "the LLM gateway only forwards POST")
			return
		}
		if !allowedLLMPath(stripFirstSegment(r.URL.Path)) {
			writeError(w, http.StatusForbidden, "the LLM gateway only forwards inference endpoints")
			return
		}
		// Stamp the start time; the proxy clones the request with its context,
		// so meterResponse reads it back off the outbound request.
		r = r.WithContext(context.WithValue(r.Context(), callStartKey{}, time.Now()))
		body, err := io.ReadAll(io.LimitReader(r.Body, m.maxBody))
		_ = r.Body.Close()
		if err != nil {
			writeError(w, http.StatusBadRequest, "reading request body")
			return
		}
		body = rewriteModel(body, rt.model)
		// Admit against the budget by reserving this call's estimated cost, so
		// N concurrent calls cannot each pass an entry check before any has
		// metered and collectively overrun the ceiling. Reserved cost is
		// released on completion and reconciled with actual usage.
		est := estimateCost(rt.ep, body)
		if !m.reserve(est) {
			writeError(w, http.StatusPaymentRequired, "over-budget: the run's LLM budget is spent")
			return
		}
		// Release from here, not from the proxy's response callbacks: on a
		// transport error (refused/DNS/TLS/timeout, or a cage that drops the
		// connection before the provider answers) ReverseProxy runs its
		// ErrorHandler and ModifyResponse never fires, so releasing there would
		// orphan the reservation and permanently wedge the budget. ServeHTTP
		// blocks until the response (stream included) is fully copied, so this
		// fires after metering on every path.
		defer m.release(est)
		r = r.WithContext(context.WithValue(r.Context(), reservationKey{}, est))
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		// Stash the request for replay before the proxy attaches the provider
		// key (a header), so a recorded request never carries one.
		if m.record {
			r = r.WithContext(context.WithValue(r.Context(), callBodyKey{}, append([]byte(nil), body...)))
		}
		rt.proxy.ServeHTTP(w, r)
	})
	return &Gateway{meter: m, agent: agent}
}

// Handler is the agent-facing API: the proxy plus the budget gate. Agents reach
// this listener; it carries no control routes, so a cage cannot raise its own
// budget by calling the gateway it talks to.
func (g *Gateway) Handler() http.Handler { return g.agent }

// Control is the operator surface: a live budget change and a spend readout. It
// is served on a separate, container-localhost listener that agents cannot
// reach, so only the daemon (through nerdctl exec) drives it.
func (g *Gateway) Control() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /budget", g.handleSetBudget)
	mux.HandleFunc("GET /spend", g.handleSpend)
	return mux
}

func (g *Gateway) handleSetBudget(w http.ResponseWriter, r *http.Request) {
	var body struct {
		MicroUSD int64 `json:"micro_usd"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "decoding request")
		return
	}
	if body.MicroUSD < 0 {
		writeError(w, http.StatusBadRequest, "budget must not be negative")
		return
	}
	g.meter.setBudget(body.MicroUSD)
	w.WriteHeader(http.StatusNoContent)
}

func (g *Gateway) handleSpend(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(g.meter.snapshot())
}

// Snapshot is the run's current spend against its budget. The gateway main
// logs one at startup so a spend read early in a run reports the configured
// budget with $0 spent, before any call has been metered.
func (g *Gateway) Snapshot() SpendReport { return g.meter.snapshot() }

// meter accumulates per-agent and total spend behind one lock; the gateway
// serves the whole tree against one budget. It reports after each debit, so
// the latest log line is always the run's current total.
type meter struct {
	mu     sync.Mutex
	budget int64
	total  int64
	// reserved is the sum of in-flight calls' estimated cost, admitted at the
	// gate and released on completion. Admitting against total+reserved (not
	// total alone) stops N concurrent calls from each reading "under budget"
	// before any has debited and collectively blowing past the ceiling.
	reserved      int64
	agents        map[string]int64
	calls         map[string]int64
	report        func(SpendReport)
	recordCall    func(CallEvent)
	recordPayload func(CallRecord)
	record        bool
	// maxBody caps a forwarded request body, resolved at New from
	// Config.MaxBodyBytes or the default.
	maxBody int64
}

// reserve admits a call while any budget headroom remains, then tentatively
// charges its estimated cost. Admitting on headroom (settled spend plus other
// in-flight reservations still below budget) rather than requiring the whole
// estimate to fit means a lone call that will cost less than its max-token
// estimate is not wrongly refused. But once one call's reservation commits the
// remaining budget, concurrent calls are refused, so N parallel calls can no
// longer each pass the gate before any debits and collectively overrun the
// ceiling: overshoot is bounded to a single in-flight call. A zero budget is
// unbounded.
func (m *meter) reserve(est int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.budget > 0 && m.total+m.reserved >= m.budget {
		return false
	}
	m.reserved += est
	return true
}

// release drops a completed call's reservation. Every reserved call must
// release exactly once on completion (success, error, or abort) so the
// reservation pool does not leak upward and wedge the run.
func (m *meter) release(est int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reserved -= est
	if m.reserved < 0 {
		m.reserved = 0
	}
}

// ceilDiv divides rounding up, so a sub-micro-USD call meters as at least 1
// rather than truncating to 0 (which would let many tiny calls run ~free).
func ceilDiv(n, d int64) int64 {
	if n <= 0 {
		return 0
	}
	return (n + d - 1) / d
}

// recordPayloadFor logs one call's full payload for replay, computing the call's
// cost the same way debit does. A no-op when no payload hook is wired.
func (m *meter) recordPayloadFor(agentKey, model string, ep Endpoint, request, response []byte, u usage, start time.Time, streamed bool) {
	if m.recordPayload == nil {
		return
	}
	cost := ceilDiv(u.PromptTokens*ep.PriceIn, 1_000_000) + ceilDiv(u.CompletionTokens*ep.PriceOut, 1_000_000)
	m.recordPayload(CallRecord{
		Agent:            agentKey,
		Model:            model,
		Request:          request,
		Response:         response,
		PromptTokens:     u.PromptTokens,
		CompletionTokens: u.CompletionTokens,
		CostMicroUSD:     cost,
		StartUnixNano:    start.UnixNano(),
		Streamed:         streamed,
	})
}

// setBudget changes the run's budget live. Raising it lets a blocked run
// continue; lowering it stops the next call. An in-flight call is not aborted.
func (m *meter) setBudget(b int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.budget = b
}

func (m *meter) debit(agentKey string, ep Endpoint, u usage, model string, start time.Time) {
	cost := ceilDiv(u.PromptTokens*ep.PriceIn, 1_000_000) + ceilDiv(u.CompletionTokens*ep.PriceOut, 1_000_000)
	m.mu.Lock()
	m.total += cost
	m.agents[agentKey] += cost
	m.calls[agentKey]++
	snap := m.snapshotLocked()
	m.mu.Unlock()
	if m.report != nil {
		m.report(snap)
	}
	if m.recordCall != nil {
		m.recordCall(CallEvent{
			Agent:            agentKey,
			Model:            model,
			PromptTokens:     u.PromptTokens,
			CompletionTokens: u.CompletionTokens,
			CostMicroUSD:     cost,
			StartUnixNano:    start.UnixNano(),
			EndUnixNano:      time.Now().UnixNano(),
		})
	}
}

// debitCost charges a precomputed cost (the admission estimate) when a call
// produced no parseable usage: an aborted stream or a usage-less 2xx. It keeps
// spend advancing so an unmetered response is never free.
func (m *meter) debitCost(agentKey string, cost int64, model string, start time.Time) {
	if cost <= 0 {
		return
	}
	m.mu.Lock()
	m.total += cost
	m.agents[agentKey] += cost
	m.calls[agentKey]++
	snap := m.snapshotLocked()
	m.mu.Unlock()
	if m.report != nil {
		m.report(snap)
	}
	if m.recordCall != nil {
		m.recordCall(CallEvent{
			Agent:         agentKey,
			Model:         model,
			CostMicroUSD:  cost,
			StartUnixNano: start.UnixNano(),
			EndUnixNano:   time.Now().UnixNano(),
		})
	}
}

// snapshot returns the run's current spend, the readout the control surface
// serves.
func (m *meter) snapshot() SpendReport {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.snapshotLocked()
}

// snapshotLocked builds the spend report; the caller holds m.mu, so both debit
// (already locked) and snapshot reuse it without a second lock.
func (m *meter) snapshotLocked() SpendReport {
	snap := SpendReport{
		TotalMicroUSD:  m.total,
		BudgetMicroUSD: m.budget,
		Agents:         make(map[string]AgentSpend, len(m.agents)),
	}
	for k, spent := range m.agents {
		snap.Agents[k] = AgentSpend{SpentMicroUSD: spent, Calls: m.calls[k]}
	}
	return snap
}

// newProxy builds the reverse proxy for one endpoint: it forwards to the
// endpoint's base URL with the agent path segment dropped, attaches the key,
// streams responses immediately, and meters cost off the way back.
func newProxy(ep Endpoint, m *meter, agentKey, model string) *httputil.ReverseProxy {
	target, _ := url.Parse(ep.BaseURL)
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = target.Scheme
			pr.Out.URL.Host = target.Host
			pr.Out.URL.Path = singleJoin(target.Path, stripFirstSegment(pr.In.URL.Path))
			pr.Out.Host = target.Host
			// Rebuild the outbound headers from a strict allowlist. The cage
			// controls the request body, but must not pass provider headers
			// through (e.g. OpenAI-Organization/OpenAI-Beta) that would change
			// billing, routing, or feature behavior under the operator's key.
			out := make(http.Header, 4)
			if ct := pr.In.Header.Get("Content-Type"); ct != "" {
				out.Set("Content-Type", ct)
			}
			if ac := pr.In.Header.Get("Accept"); ac != "" {
				out.Set("Accept", ac)
			}
			out.Set("Authorization", "Bearer "+string(ep.Key))
			// Force an uncompressed body: the meter parses the usage block as
			// JSON, and a gzip/br/zstd response would silently leave the call
			// unmetered and the budget unenforced. Completions are small.
			out.Set("Accept-Encoding", "identity")
			pr.Out.Header = out
		},
		FlushInterval:  -1,
		ModifyResponse: meterResponse(ep, m, agentKey, model),
	}
}

// callStartKey carries the call's start time to the response side through the
// request context.
type callStartKey struct{}

func callStart(ctx context.Context) time.Time {
	if t, ok := ctx.Value(callStartKey{}).(time.Time); ok {
		return t
	}
	return time.Now()
}

// callBodyKey carries the captured request body to the response side when
// recording.
type callBodyKey struct{}

func callBody(ctx context.Context) []byte {
	if b, ok := ctx.Value(callBodyKey{}).([]byte); ok {
		return b
	}
	return nil
}

// usage is the token accounting OpenAI returns. Endpoints that omit it leave
// the call unmetered; fail-soft, budget is a cost guardrail, not an isolation
// gate.
type usage struct {
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
}

// meterResponse debits the shared counter from the response's usage block.
// A non-streaming response carries usage in its JSON body; a streamed one
// carries it in the final SSE chunk, scanned as it flows to the client.
func meterResponse(ep Endpoint, m *meter, agentKey, model string) func(*http.Response) error {
	return func(resp *http.Response) error {
		ctx := resp.Request.Context()
		start := callStart(ctx)
		est := reservation(ctx)
		if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
			// The stream path settles the charge and releases the reservation in
			// streamMeter.Close, which the proxy always calls.
			sm := &streamMeter{src: resp.Body, ep: ep, meter: m, agentKey: agentKey, model: model, start: start, est: est}
			if m.record {
				sm.record = true
				sm.request = callBody(ctx)
			}
			resp.Body = sm
			return nil
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return err
		}
		var parsed struct {
			Usage usage `json:"usage"`
		}
		metered := json.Unmarshal(body, &parsed) == nil &&
			(parsed.Usage.PromptTokens > 0 || parsed.Usage.CompletionTokens > 0)
		switch {
		case metered:
			m.debit(agentKey, ep, parsed.Usage, model, start)
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			// A 2xx that carries no parseable usage (compressed, or a
			// non-standard body) still costs money upstream; charge the
			// admission estimate so an unmetered response is never free.
			m.debitCost(agentKey, est, model, start)
		}
		if m.record {
			m.recordPayloadFor(agentKey, model, ep, callBody(ctx), body, parsed.Usage, start, false)
		}
		resp.Body = io.NopCloser(bytes.NewReader(body))
		resp.ContentLength = int64(len(body))
		resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
		return nil
	}
}

// streamMeter forwards an SSE body unchanged while scanning for the usage
// chunk, metering a streamed call without buffering. rewriteModel injects
// stream_options.include_usage on the way in, so a well-behaved endpoint
// sends usage in the last chunk.
type streamMeter struct {
	src      io.ReadCloser
	ep       Endpoint
	meter    *meter
	agentKey string
	model    string
	start    time.Time
	est      int64
	buf      bytes.Buffer
	done     bool
	released bool

	// Replay capture: the stashed request body and the whole streamed
	// response, accumulated as it flows, off the client's path.
	record  bool
	request []byte
	full    bytes.Buffer
}

func (m *streamMeter) Read(p []byte) (int, error) {
	n, err := m.src.Read(p)
	if n > 0 {
		if m.record {
			m.full.Write(p[:n])
		}
		if !m.done {
			m.scan(p[:n])
		}
	}
	return n, err
}

func (m *streamMeter) scan(b []byte) {
	m.buf.Write(b)
	for {
		raw := m.buf.Bytes()
		i := bytes.IndexByte(raw, '\n')
		if i < 0 {
			return
		}
		line := bytes.TrimSpace(raw[:i])
		m.buf.Next(i + 1)
		data, ok := bytes.CutPrefix(line, []byte("data: "))
		if !ok {
			continue
		}
		var parsed struct {
			Usage *usage `json:"usage"`
		}
		if json.Unmarshal(data, &parsed) == nil && parsed.Usage != nil {
			m.meter.debit(m.agentKey, m.ep, *parsed.Usage, m.model, m.start)
			if m.record {
				m.meter.recordPayloadFor(m.agentKey, m.model, m.ep, m.request, m.full.Bytes(), *parsed.Usage, m.start, true)
			}
			m.done = true
			return
		}
	}
}

// Close settles and releases the stream's reservation. If the usage chunk was
// never seen (the cage read the content then aborted before it, or the endpoint
// omitted it), charge the admission estimate so aborting a stream is never
// cheaper than letting it meter honestly. Guarded so a double Close is a no-op.
func (m *streamMeter) Close() error {
	if !m.released {
		if !m.done {
			m.meter.debitCost(m.agentKey, m.est, m.model, m.start)
			m.done = true
		}
		m.released = true
	}
	return m.src.Close()
}

// rewriteModel sets the request's model to the resolved name and, for a
// streamed request, asks for usage in the final chunk. A non-JSON-object body
// is forwarded as is.
func rewriteModel(body []byte, model string) []byte {
	var req map[string]any
	if json.Unmarshal(body, &req) != nil {
		return body
	}
	req["model"] = model
	if stream, _ := req["stream"].(bool); stream {
		req["stream_options"] = map[string]any{"include_usage": true}
	}
	out, err := json.Marshal(req)
	if err != nil {
		return body
	}
	return out
}

// writeError answers with an OpenAI-shaped error body so the agent's client
// surfaces it as a normal API error rather than a transport failure.
func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{"message": message, "type": "mcpvessel"},
	})
}

func splitModel(s string) (provider, model string) {
	provider, model, found := strings.Cut(s, "/")
	if !found {
		return "", s
	}
	return provider, model
}

func firstSegment(path string) string {
	path = strings.TrimPrefix(path, "/")
	if i := strings.IndexByte(path, '/'); i >= 0 {
		return path[:i]
	}
	return path
}

func stripFirstSegment(path string) string {
	trimmed := strings.TrimPrefix(path, "/")
	if i := strings.IndexByte(trimmed, '/'); i >= 0 {
		return trimmed[i:]
	}
	return "/"
}

func singleJoin(a, b string) string {
	return strings.TrimSuffix(a, "/") + "/" + strings.TrimPrefix(b, "/")
}
