// Package rca generates a structured root-cause analysis document
// when a cage terminates abnormally. The cage workflow calls Generate
// after a tripwire teardown or workflow error and the document
// captures the failure reason, the impact on findings, and a
// suggested remediation. Operators read it from the audit log to
// understand what happened without grepping through cage stderr.
package rca
