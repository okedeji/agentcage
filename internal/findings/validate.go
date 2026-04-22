package findings

import (
	"errors"
	"fmt"
	"unicode/utf8"
)

var ErrInvalidFinding = errors.New("invalid finding")

const (
	maxEvidenceRequestSize  = 1 << 20 // 1MB
	maxEvidenceResponseSize = 1 << 20 // 1MB
	maxTitleLength = 500

	DefaultMaxScreenshotSize = 5 << 20 // 5MB
)

func ValidateFinding(f Finding) error {
	var errs []error

	if f.ID == "" {
		errs = append(errs, fmt.Errorf("finding ID is required"))
	}
	if f.AssessmentID == "" {
		errs = append(errs, fmt.Errorf("assessment ID is required"))
	}
	if f.CageID == "" {
		errs = append(errs, fmt.Errorf("cage ID is required"))
	}
	if f.Title == "" {
		errs = append(errs, fmt.Errorf("title is required"))
	}
	if f.VulnClass == "" {
		errs = append(errs, fmt.Errorf("vuln class is required"))
	}
	if f.Endpoint == "" {
		errs = append(errs, fmt.Errorf("endpoint is required"))
	}

	switch f.Status {
	case StatusCandidate, StatusValidated, StatusRejected:
	default:
		errs = append(errs, fmt.Errorf("invalid status: %d", f.Status))
	}

	switch f.Severity {
	case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
	default:
		errs = append(errs, fmt.Errorf("invalid severity: %d", f.Severity))
	}

	if len(errs) > 0 {
		return fmt.Errorf("%w: %w", ErrInvalidFinding, errors.Join(errs...))
	}
	return nil
}

// SanitizeLimits configures size limits for SanitizeFinding.
type SanitizeLimits struct {
	MaxScreenshotSize int64
}

// SanitizeFinding truncates oversized text fields and drops (not truncates)
// oversized binary evidence.
func SanitizeFinding(f *Finding, limits *SanitizeLimits) {
	maxScreenshot := int64(DefaultMaxScreenshotSize)
	if limits != nil && limits.MaxScreenshotSize > 0 {
		maxScreenshot = limits.MaxScreenshotSize
	}

	if len(f.Evidence.Request) > maxEvidenceRequestSize {
		f.Evidence.Request = f.Evidence.Request[:maxEvidenceRequestSize]
	}
	if len(f.Evidence.Response) > maxEvidenceResponseSize {
		f.Evidence.Response = f.Evidence.Response[:maxEvidenceResponseSize]
	}
	if len(f.Title) > maxTitleLength {
		f.Title = truncateUTF8(f.Title, maxTitleLength)
	}
	if int64(len(f.Evidence.Screenshot)) > maxScreenshot {
		f.Description += fmt.Sprintf(
			"\n\n[warning: screenshot dropped, %d bytes exceeds %d byte limit]",
			len(f.Evidence.Screenshot), maxScreenshot,
		)
		f.Evidence.Screenshot = nil
	}
}

func truncateUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	for maxBytes > 0 && !utf8.RuneStart(s[maxBytes]) {
		maxBytes--
	}
	return s[:maxBytes]
}
