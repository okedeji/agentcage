package embedded

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"github.com/nats-io/nats-server/v2/server"
)

const natsPort = 14222

// NATSService runs NATS with JetStream in-process: no subprocess, no
// binary download. The lightest embedded service.
type NATSService struct {
	srv *server.Server
	log logr.Logger
}

func NewNATSService(log logr.Logger) *NATSService {
	return &NATSService{log: log.WithValues("service", "nats")}
}

func (n *NATSService) Name() string      { return "nats" }
func (n *NATSService) IsExternal() bool   { return false }

func (n *NATSService) URL() string {
	return fmt.Sprintf("nats://localhost:%d", natsPort)
}

func (n *NATSService) Download(_ context.Context) error {
	// NATS runs in-process as a Go library. Nothing to download.
	return nil
}

func (n *NATSService) Start(_ context.Context) error {
	opts := &server.Options{
		Port:      natsPort,
		JetStream: true,
		StoreDir:  ServiceDataDir("nats"),
		NoLog:     true,
		NoSigs:    true,
	}

	srv, err := server.NewServer(opts)
	if err != nil {
		return fmt.Errorf("creating NATS server: %w", err)
	}

	srv.Start()

	if !srv.ReadyForConnections(10 * time.Second) {
		srv.Shutdown()
		return fmt.Errorf("NATS did not become ready within 10s")
	}

	n.srv = srv
	n.log.Info("nats ready", "port", natsPort, "jetstream", true)
	return nil
}

// NATSURL returns the connection string for the embedded NATS server.
func NATSURL() string {
	return fmt.Sprintf("nats://localhost:%d", natsPort)
}

func (n *NATSService) Stop(_ context.Context) error {
	if n.srv == nil {
		return nil
	}
	n.srv.Shutdown()
	n.srv.WaitForShutdown()
	n.log.Info("nats stopped")
	return nil
}

func (n *NATSService) Health(_ context.Context) error {
	if n.srv == nil {
		return fmt.Errorf("nats not running")
	}
	if !n.srv.Running() {
		return fmt.Errorf("nats server not running")
	}
	return nil
}
