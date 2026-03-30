package intervention

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPGStore(t *testing.T) {
	store := NewPGStore(nil)
	require.NotNil(t, store)
	assert.Nil(t, store.db)
}

func TestStatusFromString(t *testing.T) {
	tests := []struct {
		input string
		want  Status
	}{
		{"pending", StatusPending},
		{"resolved", StatusResolved},
		{"timed_out", StatusTimedOut},
		{"garbage", 0},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := statusFromString(tt.input)
			assert.Equal(t, tt.want, got)
			if tt.want != 0 {
				assert.Equal(t, tt.input, statusToString(got))
			}
		})
	}
}

func TestTypeFromString(t *testing.T) {
	tests := []struct {
		input string
		want  Type
	}{
		{"tripwire_escalation", TypeTripwireEscalation},
		{"payload_review", TypePayloadReview},
		{"report_review", TypeReportReview},
		{"garbage", 0},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := typeFromString(tt.input)
			assert.Equal(t, tt.want, got)
			if tt.want != 0 {
				assert.Equal(t, tt.input, typeToString(got))
			}
		})
	}
}

func TestPriorityFromString(t *testing.T) {
	tests := []struct {
		input string
		want  Priority
	}{
		{"low", PriorityLow},
		{"medium", PriorityMedium},
		{"high", PriorityHigh},
		{"critical", PriorityCritical},
		{"garbage", 0},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := priorityFromString(tt.input)
			assert.Equal(t, tt.want, got)
			if tt.want != 0 {
				assert.Equal(t, tt.input, priorityToString(got))
			}
		})
	}
}
