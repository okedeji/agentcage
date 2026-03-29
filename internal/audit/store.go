package audit

import "context"

// Store persists audit entries and digests. Implementations must ensure
// that AppendEntry is idempotent on the entry ID — duplicate appends
// (from Temporal activity retries) must succeed without creating
// duplicate entries.
type Store interface {
	AppendEntry(ctx context.Context, entry Entry) error
	GetEntries(ctx context.Context, cageID string) ([]Entry, error)
	SaveDigest(ctx context.Context, digest Digest) error
	GetDigest(ctx context.Context, cageID string) (*Digest, error)
	GetLatestDigest(ctx context.Context, assessmentID string) (*Digest, error)
}
