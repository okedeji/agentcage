package main

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/go-logr/logr"

	"github.com/okedeji/agentcage/internal/alert"
	"github.com/okedeji/agentcage/internal/config"
	"github.com/okedeji/agentcage/internal/intervention"
)

// Short enough that an unreachable webhook can't back up the
// notifier queue.
const webhookDefaultTimeout = 5 * time.Second

func setupNotifications(db *sql.DB, cfg *config.Config, log logr.Logger) (*intervention.PGStore, intervention.Notifier, *alert.Dispatcher) {
	fmt.Println("Setting up notifications...")
	store := intervention.NewPGStore(db)

	notifiers := []intervention.Notifier{intervention.NewLogNotifier(log)}
	for _, wh := range cfg.Notifications.Webhooks {
		if wh.URL == "" {
			continue
		}
		timeout := wh.Timeout
		if timeout == 0 {
			timeout = webhookDefaultTimeout
		}
		whNotifier := intervention.NewWebhookNotifier([]string{wh.URL}, timeout, log)
		if len(wh.Headers) > 0 {
			whNotifier.SetHeaders(wh.Headers)
		}
		notifiers = append(notifiers, whNotifier)
		log.Info("webhook notifications enabled", "url", wh.URL)
	}
	notifier := intervention.NewMultiNotifier(log, notifiers...)
	dispatcher := alert.NewDispatcher(notifier, log)
	return store, notifier, dispatcher
}
