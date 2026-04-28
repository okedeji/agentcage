package log

import (
	"os"
	"path/filepath"

	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
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

// NewFile creates a JSON logger that writes to the given file path.
// Used by default during init so structured logs go to a file and
// the terminal shows only the UI output.
func NewFile(path string) (logr.Logger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return logr.Discard(), err
	}
	cfg := zap.NewProductionConfig()
	cfg.OutputPaths = []string{path}
	cfg.ErrorOutputPaths = []string{path}
	zapLog, err := cfg.Build()
	if err != nil {
		return logr.Discard(), err
	}
	return zapr.NewLogger(zapLog), nil
}

// NewFileAndStderr creates a logger that writes JSON to a file and
// human-readable output to stderr. Used with --debug.
func NewFileAndStderr(path string) (logr.Logger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return logr.Discard(), err
	}

	fileCfg := zap.NewProductionEncoderConfig()
	fileEncoder := zapcore.NewJSONEncoder(fileCfg)
	fileOut, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return logr.Discard(), err
	}

	consoleCfg := zap.NewDevelopmentEncoderConfig()
	consoleEncoder := zapcore.NewConsoleEncoder(consoleCfg)

	core := zapcore.NewTee(
		zapcore.NewCore(fileEncoder, zapcore.AddSync(fileOut), zap.InfoLevel),
		zapcore.NewCore(consoleEncoder, zapcore.AddSync(os.Stderr), zap.DebugLevel),
	)
	zapLog := zap.New(core)
	return zapr.NewLogger(zapLog), nil
}
