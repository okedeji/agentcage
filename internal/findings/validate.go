package findings

import (
	"errors"
	"fmt"
)

var ErrInvalidFinding = errors.New("invalid finding")

const (
	maxEvidenceRequestSize    = 1 << 20     // 1MB
	maxEvidenceResponseSize   = 1 << 20     // 1MB
	maxEvidenceScreenshotSize = 5 << 20     // 5MB
	maxTitleLength            = 500
	maxDescriptionLength      = 10000
)

func ValidateFinding(f Finding) error {
	var errs []error

	if f.ID == "" {
		errs = append(errs, fmt.Errorf("ID is required"))
	}
	if f.AssessmentID == "" {
		errs = append(errs, fmt.Errorf("AssessmentID is required"))
	}
	if f.CageID == "" {
		errs = append(errs, fmt.Errorf("CageID is required"))
	}
	if f.Title == "" {
		errs = append(errs, fmt.Errorf("Title is required"))
	}
	if f.VulnClass == "" {
		errs = append(errs, fmt.Errorf("VulnClass is required"))
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

func SanitizeFinding(f *Finding) {
	if len(f.Evidence.Request) > maxEvidenceRequestSize {
		f.Evidence.Request = f.Evidence.Request[:maxEvidenceRequestSize]
	}
	if len(f.Evidence.Response) > maxEvidenceResponseSize {
		f.Evidence.Response = f.Evidence.Response[:maxEvidenceResponseSize]
	}
	if len(f.Evidence.Screenshot) > maxEvidenceScreenshotSize {
		f.Evidence.Screenshot = f.Evidence.Screenshot[:maxEvidenceScreenshotSize]
	}
	if len(f.Title) > maxTitleLength {
		f.Title = f.Title[:maxTitleLength]
	}
	if len(f.Description) > maxDescriptionLength {
		f.Description = f.Description[:maxDescriptionLength]
	}
}
