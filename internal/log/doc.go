// Package log builds the orchestrator's structured logger. Two
// formats: production JSON for log aggregation and dev console for
// human reading. The package wraps zap behind logr so the rest of
// the codebase only depends on the logr interface.
package log
