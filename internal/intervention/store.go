package intervention

import "context"

type ListFilters struct {
	StatusFilter *Status
	TypeFilter   *Type
	AssessmentID string
	PageSize     int
	PageToken    string
}

type Store interface {
	SaveIntervention(ctx context.Context, req Request) error
	UpdateIntervention(ctx context.Context, req Request) error
	GetIntervention(ctx context.Context, id string) (*Request, error)
	ListInterventions(ctx context.Context, filters ListFilters) ([]Request, string, error)
}
