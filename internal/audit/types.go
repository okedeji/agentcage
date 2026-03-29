package audit

import (
	"fmt"
	"time"
)

type EntryType int

const (
	EntryTypeUnspecified EntryType = iota
	EntryTypeCageProvisioned
	EntryTypeCageStarted
	EntryTypeCagePaused
	EntryTypeCageResumed
	EntryTypeCageTornDown
	EntryTypePolicyApplied
	EntryTypePolicyRemoved
	EntryTypeEgressAllowed
	EntryTypeEgressBlocked
	EntryTypePayloadAllowed
	EntryTypePayloadBlocked
	EntryTypePayloadHeld
	EntryTypeFindingEmitted
	EntryTypeFindingValidated
	EntryTypeFindingRejected
	EntryTypeTripwireFired
	EntryTypeInterventionRequested
	EntryTypeInterventionResolved
	EntryTypeIdentityIssued
	EntryTypeIdentityRevoked
	EntryTypeSecretFetched
	EntryTypeSecretRevoked
	EntryTypeLLMRequest
	EntryTypeLLMResponse
)

var entryTypeNames = map[EntryType]string{
	EntryTypeUnspecified:           "unspecified",
	EntryTypeCageProvisioned:      "cage_provisioned",
	EntryTypeCageStarted:          "cage_started",
	EntryTypeCagePaused:           "cage_paused",
	EntryTypeCageResumed:          "cage_resumed",
	EntryTypeCageTornDown:         "cage_torn_down",
	EntryTypePolicyApplied:        "policy_applied",
	EntryTypePolicyRemoved:        "policy_removed",
	EntryTypeEgressAllowed:        "egress_allowed",
	EntryTypeEgressBlocked:        "egress_blocked",
	EntryTypePayloadAllowed:       "payload_allowed",
	EntryTypePayloadBlocked:       "payload_blocked",
	EntryTypePayloadHeld:          "payload_held",
	EntryTypeFindingEmitted:       "finding_emitted",
	EntryTypeFindingValidated:     "finding_validated",
	EntryTypeFindingRejected:      "finding_rejected",
	EntryTypeTripwireFired:        "tripwire_fired",
	EntryTypeInterventionRequested: "intervention_requested",
	EntryTypeInterventionResolved: "intervention_resolved",
	EntryTypeIdentityIssued:       "identity_issued",
	EntryTypeIdentityRevoked:      "identity_revoked",
	EntryTypeSecretFetched:        "secret_fetched",
	EntryTypeSecretRevoked:        "secret_revoked",
	EntryTypeLLMRequest:           "llm_request",
	EntryTypeLLMResponse:          "llm_response",
}

func (t EntryType) String() string {
	if name, ok := entryTypeNames[t]; ok {
		return name
	}
	return fmt.Sprintf("unknown(%d)", int(t))
}

// Entry is a single record in a cage's tamper-evident audit log. Entries
// form an HMAC chain: each entry's Signature covers the entry content and
// PreviousHash, so modifying or removing any entry invalidates the chain
// from that point forward.
type Entry struct {
	ID           string
	CageID       string
	AssessmentID string
	Sequence     int64
	Type         EntryType
	Timestamp    time.Time
	Data         []byte
	KeyVersion   string
	Signature    []byte
	PreviousHash []byte
}

// KeyResolver returns the HMAC signing key for the given key version.
// This indirection supports key rotation: entries signed with older keys
// can still be verified by resolving the version recorded in each entry.
type KeyResolver func(keyVersion string) ([]byte, error)

// Digest is a signed snapshot of a chain's state at a point in time.
// Customers download and store digests independently. If the chain is
// tampered with after a digest is issued, the ChainHeadHash will no
// longer match, and the customer can detect the tampering without
// running any infrastructure.
type Digest struct {
	AssessmentID  string
	CageID        string
	ChainHeadHash []byte
	EntryCount    int64
	KeyVersion    string
	Signature     []byte
	IssuedAt      time.Time
}
