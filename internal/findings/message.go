package findings

const (
	SchemaVersionV1      = "v1"
	CurrentSchemaVersion = SchemaVersionV1
)

// Message is the NATS envelope for findings emitted by the sidecar.
// Every NATS message carries a schema_version so the coordinator can
// deserialize messages from cages running different deploy versions.
type Message struct {
	SchemaVersion string  `json:"schema_version"`
	Finding       Finding `json:"finding"`
}

// Subject returns the NATS subject for findings within an assessment.
func Subject(assessmentID string) string {
	return "assessment." + assessmentID + ".findings"
}

// DeadLetterSubject returns the dead letter subject for findings that
// failed processing after exhausting retries.
func DeadLetterSubject(assessmentID string) string {
	return "assessment." + assessmentID + ".findings.dead"
}
