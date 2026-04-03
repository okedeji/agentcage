package findings

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
)

type FindingStore interface {
	SaveFinding(ctx context.Context, finding Finding) error
	FindingExists(ctx context.Context, findingID string) (bool, error)
	GetByAssessment(ctx context.Context, assessmentID string, status Status) ([]Finding, error)
	UpdateStatus(ctx context.Context, findingID string, status Status) error
}

type Coordinator struct {
	store  FindingStore
	bloom  *BloomFilter
	limits *SanitizeLimits
	logger logr.Logger
}

func NewCoordinator(store FindingStore, bloom *BloomFilter, limits *SanitizeLimits, logger logr.Logger) *Coordinator {
	return &Coordinator{store: store, bloom: bloom, limits: limits, logger: logger}
}

func (c *Coordinator) HandleMessage(ctx context.Context, msg Message) error {
	if err := ValidateFinding(msg.Finding); err != nil {
		c.logger.Info("dropping invalid finding", "error", err)
		return nil
	}

	SanitizeFinding(&msg.Finding, c.limits)

	if c.bloom.MayContain(msg.Finding.ID) {
		exists, err := c.store.FindingExists(ctx, msg.Finding.ID)
		if err != nil {
			return fmt.Errorf("checking finding %s existence: %w", msg.Finding.ID, err)
		}
		if exists {
			c.logger.V(1).Info("duplicate finding, skipping", "finding_id", msg.Finding.ID)
			return nil
		}
	}

	if err := c.store.SaveFinding(ctx, msg.Finding); err != nil {
		return fmt.Errorf("saving finding %s: %w", msg.Finding.ID, err)
	}

	c.bloom.Add(msg.Finding.ID)

	c.logger.Info("finding processed",
		"finding_id", msg.Finding.ID,
		"assessment_id", msg.Finding.AssessmentID,
		"vuln_class", msg.Finding.VulnClass,
	)

	return nil
}
