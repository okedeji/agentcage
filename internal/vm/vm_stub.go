//go:build !darwin

package vm

import (
	"context"
	"errors"
)

var errNotSupported = errors.New("VM support requires macOS with Apple Virtualization.framework")

// LinuxVM is a stub for non-darwin builds.
type LinuxVM struct{}

func Boot(_ context.Context, _ Config) (*LinuxVM, error) {
	return nil, errNotSupported
}

func (v *LinuxVM) Shutdown(_ context.Context) error { return errNotSupported }
func (v *LinuxVM) IP() string                       { return "" }
func (v *LinuxVM) Wait() error                      { return errNotSupported }
func (v *LinuxVM) IsRunning() bool                  { return false }
