package log

import (
	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"go.uber.org/zap"
)

// New creates a production logger with JSON output suitable for structured log
// aggregation. Callers should use WithValues to attach cage_id, assessment_id,
// and other context keys before passing the logger down the call chain.
func New() (logr.Logger, error) {
	zapLog, err := zap.NewProduction()
	if err != nil {
		return logr.Discard(), err
	}
	return zapr.NewLogger(zapLog), nil
}

// NewDev creates a development logger with human-readable console output and
// debug-level verbosity.
func NewDev() (logr.Logger, error) {
	zapLog, err := zap.NewDevelopment()
	if err != nil {
		return logr.Discard(), err
	}
	return zapr.NewLogger(zapLog), nil
}
