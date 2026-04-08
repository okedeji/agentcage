// Command payload-proxy runs inside each cage as the egress
// inspection point. It reverse-proxies HTTP traffic from the agent
// to the upstream target, matches each request against the cage's
// vuln-class blocklist (compiled once at startup), and either
// forwards or blocks based on the match. Requests to the LLM
// endpoint are metered for token accounting but never inspected.
package main
