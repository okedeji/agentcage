package cage

import (
	"errors"
	"fmt"
)

var validTransitions = map[State][]State{
	StatePending:      {StateProvisioning, StateFailed},
	StateProvisioning: {StateRunning, StateFailed},
	StateRunning:      {StatePaused, StateTearingDown, StateFailed},
	StatePaused:       {StateRunning, StateTearingDown, StateFailed},
	StateTearingDown:  {StateCompleted, StateFailed},
}

var ErrInvalidTransition = errors.New("invalid state transition")

func ValidateTransition(from, to State) error {
	allowed, ok := validTransitions[from]
	if !ok {
		return fmt.Errorf("%w: no transitions from %s", ErrInvalidTransition, from)
	}
	for _, s := range allowed {
		if s == to {
			return nil
		}
	}
	return fmt.Errorf("%w: %s to %s", ErrInvalidTransition, from, to)
}
