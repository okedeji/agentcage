package agentcage.scope

deny contains msg if {
	count(input.hosts) == 0
	msg := "scope must include at least one host"
}

deny contains msg if {
	some h
	input.hosts[h] == "*"
	msg := "wildcard hosts are not allowed"
}

deny contains msg if {
	some h
	contains(input.hosts[h], "*")
	input.hosts[h] != "*"
	msg := sprintf("wildcard in host not allowed: %s", [input.hosts[h]])
}

deny contains msg if {
	some h
	net.cidr_contains("10.0.0.0/8", input.hosts[h])
	msg := sprintf("private IP range not allowed: %s", [input.hosts[h]])
}

deny contains msg if {
	some h
	net.cidr_contains("172.16.0.0/12", input.hosts[h])
	msg := sprintf("private IP range not allowed: %s", [input.hosts[h]])
}

deny contains msg if {
	some h
	net.cidr_contains("192.168.0.0/16", input.hosts[h])
	msg := sprintf("private IP range not allowed: %s", [input.hosts[h]])
}

deny contains msg if {
	some h
	input.hosts[h] == "localhost"
	msg := "localhost not allowed in scope"
}

deny contains msg if {
	some h
	startswith(input.hosts[h], "127.")
	msg := sprintf("loopback address not allowed: %s", [input.hosts[h]])
}

deny contains msg if {
	some h
	input.hosts[h] == "::1"
	msg := "IPv6 loopback not allowed in scope"
}

deny contains msg if {
	some h
	infrastructure_hosts[input.hosts[h]]
	msg := sprintf("cannot target agentcage infrastructure: %s", [input.hosts[h]])
}

infrastructure_hosts := {
	"orchestrator.agentcage.internal",
	"vault.agentcage.internal",
	"spire.agentcage.internal",
	"nats.agentcage.internal",
	"temporal.agentcage.internal",
	"postgres.agentcage.internal",
	"llm-gateway.agentcage.internal",
}
