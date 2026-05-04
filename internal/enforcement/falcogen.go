package enforcement

import (
	"fmt"
	"os"
	"path/filepath"
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

// detectConditions maps rule names (the keys users write in the
// monitoring config) to Falco detection conditions. The user picks
// the rule and the action; the detection logic is locked here so a
// misconfigured user can't relax what counts as suspicious.
var detectConditions = map[string]struct {
	condition string
	output    string
	priority  string
}{
	"privileged_shell": {
		condition: "spawned_process and proc.name in (bash, sh, dash, zsh) and user.uid = 0",
		output:    "Privileged shell spawned user=%user.name command=%proc.cmdline pid=%proc.pid",
		priority:  "WARNING",
	},
	"any_shell": {
		condition: "spawned_process and proc.name in (bash, sh, dash, zsh)",
		output:    "Shell spawned command=%proc.cmdline pid=%proc.pid",
		priority:  "CRITICAL",
	},
	"sensitive_file_write": {
		condition: "open_write and (fd.name startswith /etc/ or fd.name startswith /proc/ or fd.name startswith /sys/)",
		output:    "Sensitive file write file=%fd.name command=%proc.cmdline pid=%proc.pid",
		priority:  "WARNING",
	},
	"any_file_write": {
		condition: "open_write",
		output:    "File write file=%fd.name command=%proc.cmdline pid=%proc.pid",
		priority:  "WARNING",
	},
	"privilege_escalation": {
		condition: "(evt.type in (setuid, setgid, setreuid, setregid) or proc.name = sudo)",
		output:    "Privilege escalation attempt syscall=%evt.type command=%proc.cmdline pid=%proc.pid",
		priority:  "CRITICAL",
	},
	"fork_bomb": {
		condition: "evt.type = clone",
		output:    "Process fork command=%proc.cmdline parent=%proc.pname pid=%proc.pid",
		priority:  "NOTICE",
	},
	"unexpected_network": {
		condition: "evt.type in (connect, sendto) and fd.type = ipv4",
		output:    "Network connection dest=%fd.sip:%fd.sport command=%proc.cmdline pid=%proc.pid",
		priority:  "NOTICE",
	},
	"lateral_movement": {
		condition: "evt.type in (connect, sendto) and fd.sport in (22, 3389, 445)",
		output:    "Lateral movement attempt dest=%fd.sip:%fd.sport command=%proc.cmdline pid=%proc.pid",
		priority:  "CRITICAL",
	},
	"unexpected_process": {
		condition: "spawned_process and not proc.name in (%s)",
		output:    "Unexpected process process=%proc.name command=%proc.cmdline pid=%proc.pid",
		priority:  "CRITICAL",
	},
	"kernel_module": {
		condition: "(evt.type in (init_module, finit_module) or proc.name in (insmod, modprobe))",
		output:    "Kernel module load attempt command=%proc.cmdline pid=%proc.pid",
		priority:  "CRITICAL",
	},
	"ptrace": {
		condition: "evt.type = ptrace and evt.arg.request in (PTRACE_ATTACH, PTRACE_SEIZE)",
		output:    "Ptrace attach to process target=%proc.pid command=%proc.cmdline pid=%proc.pid",
		priority:  "CRITICAL",
	},
	"mount": {
		condition: "evt.type in (mount, umount2)",
		output:    "Mount operation command=%proc.cmdline pid=%proc.pid",
		priority:  "CRITICAL",
	},
	"container_escape": {
		condition: "open_read and (fd.name startswith /var/run/docker.sock or fd.name startswith /proc/1/root or fd.name startswith /proc/1/ns)",
		output:    "Container escape attempt file=%fd.name command=%proc.cmdline pid=%proc.pid",
		priority:  "CRITICAL",
	},
	"raw_socket": {
		condition: "evt.type = socket and evt.arg.type in (SOCK_RAW, SOCK_PACKET)",
		output:    "Raw socket created command=%proc.cmdline pid=%proc.pid",
		priority:  "CRITICAL",
	},
	"dns_exfil": {
		condition: "evt.type in (connect, sendto) and fd.sport = 53 and fd.type = ipv4",
		output:    "DNS query dest=%fd.sip command=%proc.cmdline pid=%proc.pid",
		priority:  "NOTICE",
	},
	"large_read": {
		condition: "open_read and evt.rawres > 1048576",
		output:    "Large file read file=%fd.name bytes=%evt.rawres command=%proc.cmdline pid=%proc.pid",
		priority:  "WARNING",
	},
	"persistence": {
		condition: "(open_write and fd.name startswith /var/spool/cron) or (proc.name in (crontab, at, atd))",
		output:    "Persistence attempt via scheduled job file=%fd.name command=%proc.cmdline pid=%proc.pid",
		priority:  "CRITICAL",
	},
	"download_exec": {
		condition: "spawned_process and proc.name in (curl, wget) and proc.pcmdline contains chmod",
		output:    "Download and execute command=%proc.cmdline parent=%proc.pcmdline pid=%proc.pid",
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

		for ruleName, action := range mc.Rules {
			def, ok := detectConditions[ruleName]
			if !ok {
				fmt.Fprintf(os.Stderr, "warning: unknown monitoring rule %q in %s config, skipping\n", ruleName, cageType)
				continue
			}

			if !isValidTripwireAction(action) {
				fmt.Fprintf(os.Stderr, "warning: unknown action %q for rule %q in %s config, defaulting to log\n", action, ruleName, cageType)
			}

			fullName := fmt.Sprintf("%s in %s cage", humanizeRuleName(ruleName), cageType)
			condition := def.condition
			output := def.output

			// For allowlist-based rules, substitute the process list
			if strings.Contains(condition, "%s") {
				if len(mc.AllowedProcesses) > 0 {
					condition = fmt.Sprintf(condition, strings.Join(mc.AllowedProcesses, ", "))
				} else {
					fmt.Fprintf(os.Stderr, "warning: rule %q in %s requires allowed_processes but list is empty, skipping\n", ruleName, cageType)
					continue
				}
			}

			rules = append(rules, FalcoRuleOutput{
				Rule:      fullName,
				Desc:      fmt.Sprintf("Detects %s in %s cages", humanizeRuleName(ruleName), cageType),
				Condition: condition,
				Output:    fmt.Sprintf("%s in %s cage: %s", humanizeRuleName(ruleName), cageType, output),
				Priority:  def.priority,
				Tags:      []string{"agentcage", cageType, ruleName},
			})

			tripwire.Rules[fullName] = parseTripwireAction(action)
		}

		allRules[cageType] = rules
		allTripwires[cageType] = tripwire
	}

	return allRules, allTripwires
}

// RenderFalcoYAML serializes generated rules to Falco YAML format.
// Macros our rules reference. Defined here so we don't depend on
// Falco's bundled falco_rules.yaml which may not be installed.
const falcoMacroPreamble = `- macro: spawned_process
  condition: evt.type in (execve, execveat)

- macro: open_read
  condition: evt.type in (open, openat, openat2) and evt.is_open_read = true and fd.typechar = f

- macro: open_write
  condition: evt.type in (open, openat, openat2) and evt.is_open_write = true and fd.typechar = f

`

func RenderFalcoYAML(rules map[string][]FalcoRuleOutput) string {
	var b strings.Builder
	b.WriteString(falcoMacroPreamble)
	for _, ruleSet := range rules {
		for _, r := range ruleSet {
			fmt.Fprintf(&b, "- rule: %s\n", r.Rule)
			fmt.Fprintf(&b, "  desc: %s\n", r.Desc)
			fmt.Fprintf(&b, "  condition: %s\n", r.Condition)
			fmt.Fprintf(&b, "  output: \"%s\"\n", escapeYAMLString(r.Output))
			fmt.Fprintf(&b, "  priority: %s\n", r.Priority)
			if len(r.Tags) > 0 {
				fmt.Fprintf(&b, "  tags: [%s]\n", strings.Join(r.Tags, ", "))
			}
			b.WriteString("\n")
		}
	}
	return b.String()
}

// WriteFalcoRules writes generated rules to a directory as Falco YAML.
// The Falco daemon loads rules from this directory at startup.
func WriteFalcoRules(rules map[string][]FalcoRuleOutput, dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating Falco rules directory %s: %w", dir, err)
	}
	dest := filepath.Join(dir, "agentcage_rules.yaml")
	if err := os.WriteFile(dest, []byte(RenderFalcoYAML(rules)), 0644); err != nil {
		return fmt.Errorf("writing Falco rules to %s: %w", dest, err)
	}
	return nil
}

func escapeYAMLString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}

func humanizeRuleName(name string) string {
	return strings.ReplaceAll(name, "_", " ")
}

func isValidTripwireAction(s string) bool {
	switch strings.ToLower(s) {
	case "log", "log_and_continue", "human_review", "kill", "immediate_teardown":
		return true
	default:
		return false
	}
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
