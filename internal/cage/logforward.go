package cage

import "context"

type LogCollector interface {
	Forward(ctx context.Context, cageID string, source string, line []byte) error
	Close() error
}

type LogSource string

const (
	LogSourcePayloadProxy    LogSource = "payload-proxy"
	LogSourceFindingsSidecar LogSource = "findings-sidecar"
	LogSourceAgent           LogSource = "agent"
	LogSourceDNSResolver     LogSource = "dns-resolver"
)

type VsockConfig struct {
	GuestCID uint32
	Port     uint32
}
