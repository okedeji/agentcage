// Package migrations embeds all SQL migration files and applies them
// transactionally via the Up function. Each migration runs inside its
// own transaction and is tracked in a schema_migrations table so
// re-running Up is safe. Down rolls back the last N applied
// migrations in reverse order.
package migrations
