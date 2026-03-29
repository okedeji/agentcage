package enforcement

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/okedeji/agentcage/internal/cage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFalcoHandler_HandleAlert(t *testing.T) {
	handler := NewFalcoHandler(DefaultRuleSets())
	ctx := context.Background()

	tests := []struct {
		name       string
		cageType   cage.Type
		ruleName   string
		wantPolicy TripwirePolicy
		wantErr    bool
	}{
		{
			name:       "discovery privilege escalation triggers teardown",
			cageType:   cage.TypeDiscovery,
			ruleName:   "Privilege Escalation Attempt in Discovery Cage",
			wantPolicy: TripwireImmediateTeardown,
		},
		{
			name:       "discovery sensitive file write logs and continues",
			cageType:   cage.TypeDiscovery,
			ruleName:   "Sensitive File Write in Discovery Cage",
			wantPolicy: TripwireLogAndContinue,
		},
		{
			name:       "discovery privileged shell triggers human review",
			cageType:   cage.TypeDiscovery,
			ruleName:   "Unexpected Privileged Shell in Discovery Cage",
			wantPolicy: TripwireHumanReview,
		},
		{
			name:       "discovery unknown rule falls back to default",
			cageType:   cage.TypeDiscovery,
			ruleName:   "Some Unknown Rule",
			wantPolicy: TripwireLogAndContinue,
		},
		{
			name:       "validator shell spawn triggers teardown",
			cageType:   cage.TypeValidator,
			ruleName:   "Any Shell Spawn in Validator Cage",
			wantPolicy: TripwireImmediateTeardown,
		},
		{
			name:       "validator file write triggers human review",
			cageType:   cage.TypeValidator,
			ruleName:   "Any File Write in Validator Cage",
			wantPolicy: TripwireHumanReview,
		},
		{
			name:       "validator unknown rule falls back to human review",
			cageType:   cage.TypeValidator,
			ruleName:   "Some Unknown Rule",
			wantPolicy: TripwireHumanReview,
		},
		{
			name:       "escalation lateral movement triggers teardown",
			cageType:   cage.TypeEscalation,
			ruleName:   "Lateral Movement Attempt in Escalation Cage",
			wantPolicy: TripwireImmediateTeardown,
		},
		{
			name:       "escalation unknown rule falls back to human review",
			cageType:   cage.TypeEscalation,
			ruleName:   "Some Unknown Rule",
			wantPolicy: TripwireHumanReview,
		},
		{
			name:     "unknown cage type returns error",
			cageType: cage.Type(99),
			ruleName: "Any Rule",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alert := FalcoAlert{
				RuleName:  tt.ruleName,
				Priority:  "CRITICAL",
				Output:    "test output",
				CageID:    "cage-123",
				Timestamp: time.Now(),
			}

			policy, err := handler.HandleAlert(ctx, tt.cageType, alert)

			if tt.wantErr {
				require.Error(t, err)
				assert.True(t, errors.Is(err, ErrUnknownCageType))
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantPolicy, policy)
		})
	}
}
