package cage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/go-logr/logr"
)

// PayloadHoldNotification is sent by the in-cage payload proxy when a
// request matches a flag pattern and is held for human review.
type PayloadHoldNotification struct {
	HoldID string `json:"hold_id"`
	CageID string `json:"cage_id"`
	Method string `json:"method"`
	URL    string `json:"url"`
	Reason string `json:"reason"`
}

// HoldRecord tracks a held payload so the resolution can be relayed
// back to the proxy's control endpoint inside the VM.
type HoldRecord struct {
	CageID  string
	VMIP    string
	HoldID  string
	EnqueuedAt time.Time
}

// PayloadHoldHandler receives hold notifications from in-cage proxies,
// enqueues interventions, and relays decisions back when resolved.
type PayloadHoldHandler struct {
	enqueuer         InterventionEnqueuer
	interventionTTL  time.Duration
	controlPort      string
	httpClient       *http.Client
	mu               sync.Mutex
	holds            map[string]*HoldRecord // keyed by intervention ID
	vmIPs            map[string]string      // cage ID -> VM IP
	log              logr.Logger
}

type PayloadHoldConfig struct {
	Enqueuer        InterventionEnqueuer
	InterventionTTL time.Duration
	ControlPort     string
	Log             logr.Logger
}

func NewPayloadHoldHandler(cfg PayloadHoldConfig) *PayloadHoldHandler {
	return &PayloadHoldHandler{
		enqueuer:        cfg.Enqueuer,
		interventionTTL: cfg.InterventionTTL,
		controlPort:     cfg.ControlPort,
		httpClient:      &http.Client{Timeout: 10 * time.Second},
		holds:           make(map[string]*HoldRecord),
		vmIPs:           make(map[string]string),
		log:             cfg.Log.WithValues("component", "payload-hold-handler"),
	}
}

// RegisterVM records the VM IP for a cage so hold decisions can be relayed.
func (h *PayloadHoldHandler) RegisterVM(cageID, vmIP string) {
	h.mu.Lock()
	h.vmIPs[cageID] = vmIP
	h.mu.Unlock()
}

// UnregisterVM removes a cage's VM IP and any pending holds on teardown.
func (h *PayloadHoldHandler) UnregisterVM(cageID string) {
	h.mu.Lock()
	delete(h.vmIPs, cageID)
	for id, record := range h.holds {
		if record.CageID == cageID {
			delete(h.holds, id)
		}
	}
	h.mu.Unlock()
}

// ServeHTTP handles POST /payload-hold from in-cage proxies.
func (h *PayloadHoldHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var notif PayloadHoldNotification
	if err := json.NewDecoder(r.Body).Decode(&notif); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	h.mu.Lock()
	vmIP := h.vmIPs[notif.CageID]
	h.mu.Unlock()

	if vmIP == "" {
		h.log.Info("hold notification for unknown cage, ignoring", "cage_id", notif.CageID, "hold_id", notif.HoldID)
		http.Error(w, "unknown cage", http.StatusNotFound)
		return
	}

	description := fmt.Sprintf("payload held: %s %s (%s)", notif.Method, notif.URL, notif.Reason)
	contextData, _ := json.Marshal(notif)

	interventionID, err := h.enqueuer.Enqueue(
		r.Context(),
		InterventionPayloadReview,
		InterventionPriorityHigh,
		notif.CageID, "",
		description, contextData,
		h.interventionTTL,
	)
	if err != nil {
		h.log.Error(err, "enqueuing payload hold intervention", "cage_id", notif.CageID, "hold_id", notif.HoldID)
		http.Error(w, "failed to enqueue intervention", http.StatusInternalServerError)
		return
	}

	h.mu.Lock()
	h.holds[interventionID] = &HoldRecord{
		CageID:     notif.CageID,
		VMIP:       vmIP,
		HoldID:     notif.HoldID,
		EnqueuedAt: time.Now(),
	}
	h.mu.Unlock()

	h.log.Info("payload hold intervention enqueued",
		"intervention_id", interventionID,
		"cage_id", notif.CageID,
		"hold_id", notif.HoldID,
	)
	w.WriteHeader(http.StatusAccepted)
}

// ReleaseHold relays a decision back to the proxy inside the VM.
func (h *PayloadHoldHandler) ReleaseHold(ctx context.Context, interventionID string, allow bool) error {
	h.mu.Lock()
	record, ok := h.holds[interventionID]
	if ok {
		delete(h.holds, interventionID)
	}
	h.mu.Unlock()

	if !ok {
		return fmt.Errorf("no hold record for intervention %s", interventionID)
	}

	decision := "block"
	if allow {
		decision = "allow"
	}

	payload, _ := json.Marshal(map[string]string{"decision": decision})
	releaseURL := fmt.Sprintf("http://%s/hold/%s/release", net.JoinHostPort(record.VMIP, h.controlPort), record.HoldID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, releaseURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("creating release request for hold %s: %w", record.HoldID, err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("releasing hold %s on VM %s: %w", record.HoldID, record.VMIP, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("proxy rejected hold release %s: status %d", record.HoldID, resp.StatusCode)
	}

	h.log.Info("payload hold released", "intervention_id", interventionID, "hold_id", record.HoldID, "decision", decision)
	return nil
}
