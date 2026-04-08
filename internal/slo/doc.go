// Package slo measures service-level indicators and tracks the
// remaining error budget for each one. Indicators include cage
// startup latency, teardown completeness, egress enforcement,
// payload firewall, intervention response time, audit log delivery,
// gateway availability, findings bus delivery, and fleet warm
// buffer. The tracker records measurements over a rolling window
// and computes burn rate so operators can tell when a degradation
// is sustained instead of a blip.
package slo
