package enforcement

import (
	"fmt"
	"strings"

	"github.com/okedeji/agentcage/internal/config"
)

// FalcoRuleOutput is a generated Falco rule ready for the Falco daemon.
type FalcoRuleOutput struct {
	Rule      string
	Desc      string
	Condition string
	Output    string
	Priority  string
	Tags      []string
}

// GeneratedTripwire maps a generated Falco rule name to the action agentcage
// should take when the rule fires.
type GeneratedTripwire struct {
	Rules         map[string]TripwirePolicy
	DefaultAction TripwirePolicy
}

// detectConditions maps human-readable detect strings from the config to
// Falco condition syntax. agentcage owns this mapping — the user writes
// "root shell spawn", agentcage translates to Falco syntax.
var detectConditions = map[string]struct {
	condition string
	output    string
	priority  string
}{
	"root shell spawn": {
		condition: "spawned_process and proc.name in (bash, sh, dash, zsh) and proc.uid = 0 and container.id != host",
		output:    "Privileged shell spawned (user=%user.name command=%proc.cmdline container=%container.id)",
		priority:  "WARNING",
	},
	"any shell spawn": {
		condition: "spawned_process and proc.name in (bash, sh, dash, zsh) and container.id != host",
		output:    "Shell spawned (command=%proc.cmdline container=%container.id)",
		priority:  "CRITICAL",
	},
	"write to /etc, /proc, /sys": {
		condition: "open_write and (fd.name startswith /etc/ or fd.name startswith /proc/ or fd.name startswith /sys/) and container.id != host",
		output:    "Sensitive file write (file=%fd.name command=%proc.cmdline container=%container.id)",
		priority:  "WARNING",
	},
	"any filesystem write": {
		condition: "open_write and container.id != host",
		output:    "File write (file=%fd.name command=%proc.cmdline container=%container.id)",
		priority:  "WARNING",
	},
	"setuid, setgid, sudo": {
		condition: "(evt.type in (setuid, setgid, setreuid, setregid) or proc.name = sudo) and container.id != host",
		output:    "Privilege escalation attempt (syscall=%evt.type command=%proc.cmdline container=%container.id)",
		priority:  "CRITICAL",
	},
	"rapid process forking": {
		condition: "evt.type = clone and container.id != host",
		output:    "Process fork (command=%proc.cmdline parent=%proc.pname container=%container.id)",
		priority:  "NOTICE",
	},
	"connection outside target scope": {
		condition: "evt.type in (connect, sendto) and fd.type = ipv4 and container.id != host",
		output:    "Network connection (dest=%fd.sip:%fd.sport command=%proc.cmdline container=%container.id)",
		priority:  "NOTICE",
	},
	"SSH, RDP, SMB connections": {
		condition: "evt.type in (connect, sendto) and fd.sport in (22, 3389, 445) and container.id != host",
		output:    "Lateral movement attempt (dest=%fd.sip:%fd.sport command=%proc.cmdline container=%container.id)",
		priority:  "CRITICAL",
	},
	"process not in allowlist": {
		condition: "spawned_process and not proc.name in (%s) and container.id != host",
		output:    "Unexpected process (process=%proc.name command=%proc.cmdline container=%container.id)",
		priority:  "CRITICAL",
	},
}

// GenerateFalcoRules produces Falco rules and tripwire policies from the
// monitoring config. Returns rules per cage type and the corresponding
// tripwire action mappings.
func GenerateFalcoRules(monitoring map[string]config.MonitoringConfig) (map[string][]FalcoRuleOutput, map[string]GeneratedTripwire) {
	allRules := make(map[string][]FalcoRuleOutput)
	allTripwires := make(map[string]GeneratedTripwire)

	for cageType, mc := range monitoring {
		var rules []FalcoRuleOutput
		tripwire := GeneratedTripwire{
			Rules:         make(map[string]TripwirePolicy),
			DefaultAction: parseTripwireAction(mc.DefaultAction),
		}

		for ruleName, mr := range mc.Rules {
			def, ok := detectConditions[mr.Detect]
			if !ok {
				continue
			}

			fullName := fmt.Sprintf("%s in %s cage", humanizeRuleName(ruleName), cageType)
			condition := def.condition
			output := def.output

			// For allowlist-based rules, substitute the process list
			if strings.Contains(condition, "%s") {
				if len(mc.AllowedProcesses) > 0 {
					condition = fmt.Sprintf(condition, strings.Join(mc.AllowedProcesses, ", "))
				} else {
					continue
				}
			}

			rules = append(rules, FalcoRuleOutput{
				Rule:      fullName,
				Desc:      fmt.Sprintf("Detects %s in %s cages", mr.Detect, cageType),
				Condition: condition,
				Output:    fmt.Sprintf("%s in %s cage (%s)", humanizeRuleName(ruleName), cageType, output),
				Priority:  def.priority,
				Tags:      []string{"agentcage", cageType, ruleName},
			})

			tripwire.Rules[fullName] = parseTripwireAction(mr.Action)
		}

		allRules[cageType] = rules
		allTripwires[cageType] = tripwire
	}

	return allRules, allTripwires
}

func humanizeRuleName(name string) string {
	return strings.ReplaceAll(name, "_", " ")
}

func parseTripwireAction(s string) TripwirePolicy {
	// Map the short config action names to the existing policy constants.
	switch strings.ToLower(s) {
	case "log", "log_and_continue":
		return TripwireLogAndContinue
	case "human_review":
		return TripwireHumanReview
	case "kill", "immediate_teardown":
		return TripwireImmediateTeardown
	default:
		return TripwireLogAndContinue
	}
}
