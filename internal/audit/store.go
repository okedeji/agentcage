package audit

import "context"

// Store persists audit entries and digests. AppendEntry must be
// idempotent on the entry ID. Temporal activity retries will call it
// with the same entry, and a duplicate insert would break the chain.
type Store interface {
	AppendEntry(ctx context.Context, entry Entry) error
	GetEntries(ctx context.Context, cageID string) ([]Entry, error)
	SaveDigest(ctx context.Context, digest Digest) error
	GetDigest(ctx context.Context, cageID string) (*Digest, error)
	GetLatestDigest(ctx context.Context, assessmentID string) (*Digest, error)
}
