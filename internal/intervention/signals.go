package intervention

const (
	SignalIntervention = "intervention"
	SignalReportReview = "report_review"
	SignalProofGap     = "proof_gap"
)

// ProofGapSignal is the Temporal signal payload sent to an assessment
// workflow when an operator resolves a proof_gap intervention.
type ProofGapSignal struct {
	InterventionID string         `json:"intervention_id"`
	Action         ProofGapAction `json:"action"`
	Rationale      string         `json:"rationale"`
}

// InterventionSignal is the Temporal signal payload sent to a cage workflow
// when an operator resolves a tripwire or payload review intervention.
type InterventionSignal struct {
	Action      Action            `json:"action"`
	Rationale   string            `json:"rationale"`
	Adjustments map[string]string `json:"adjustments,omitempty"`
}

// ReportReviewSignal is the Temporal signal payload sent to an assessment
// workflow when an operator resolves a report review.
type ReportReviewSignal struct {
	Decision    ReviewDecision    `json:"decision"`
	Rationale   string            `json:"rationale"`
	Adjustments []FindingAdjustment `json:"adjustments,omitempty"`
}
