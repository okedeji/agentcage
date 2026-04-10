package envvar

import "os"

const (
	Home     = "AGENTCAGE_HOME"
	Config   = "AGENTCAGE_CONFIG"
	GRPCAddr = "AGENTCAGE_GRPC_ADDR"
	TLSCert  = "AGENTCAGE_TLS_CERT"
	TLSKey   = "AGENTCAGE_TLS_KEY"
	TLSCA    = "AGENTCAGE_TLS_CA"
	LLMKey   = "AGENTCAGE_LLM_API_KEY"
	Temporal = "AGENTCAGE_TEMPORAL_API_KEY"
	FleetKey = "AGENTCAGE_FLEET_API_KEY"

	DefaultGRPCAddr = "localhost:9090"
)

func Get(name string) string { return os.Getenv(name) }

func GRPCAddress() string {
	if addr := Get(GRPCAddr); addr != "" {
		return addr
	}
	return DefaultGRPCAddr
}
