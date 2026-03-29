package cage

// EventSubject returns the NATS subject for cage lifecycle events.
func EventSubject(cageID string) string {
	return "cage." + cageID + ".events"
}
