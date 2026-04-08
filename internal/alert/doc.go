// Package alert dispatches operational alert events to the
// intervention notification system. Alerts come from two sources:
// policy violations (OPA rejections, scope violations) and
// behavioral tripwires (Falco rules). Dispatch is asynchronous and
// fire-and-forget so it never blocks the caller.
//
// Critical alerts are always queued. Normal alerts are dropped when
// the queue is full and a suppression count is reported on the next
// successful send, so an alert storm can't take the orchestrator
// down with itself.
package alert
