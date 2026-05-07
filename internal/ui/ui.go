package ui

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"
)

var (
	subtle  = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	bold    = lipgloss.NewStyle().Bold(true)
	green   = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	yellow  = lipgloss.NewStyle().Foreground(lipgloss.Color("11"))
	red     = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	cyan    = lipgloss.NewStyle().Foreground(lipgloss.Color("14"))
	magenta = lipgloss.NewStyle().Foreground(lipgloss.Color("13"))

	keyStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("14")).Width(12)
	valStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("255"))
)

var verbose bool

// SetVerbose controls whether Step, OK, and Section produce output.
// Fail and Warn always print regardless of this setting.
func SetVerbose(v bool) { verbose = v }

// IsVerbose returns the current verbose state.
func IsVerbose() bool { return verbose }

// Header prints a single-line version header.
func Header(version string) {
	fmt.Println()
	fmt.Println("  " + bold.Render("agentcage") + subtle.Render(" v"+version))
	fmt.Println()
}

const banner = `
                        __
   ____ _____ ____  ___/ /_____  ____ _____ ____
  / __ '/ __ '/ _ \/ __ __/ __|/ __ '/ __ '/ _ \
 / /_/ / /_/ /  __/ / / / /__/ /_/ / /_/ /  __/
 \__,_/\__, /\___/_/ /_/\___/\__,_/\__, /\___/
       /____/                      /____/`

// Banner prints the agentcage startup banner with version.
func Banner(version, platform string) {
	fmt.Println(cyan.Render(banner))
	fmt.Println()
	info := fmt.Sprintf("v%s", version)
	if platform != "" {
		info += subtle.Render(" (" + platform + ")")
	}
	fmt.Println("  " + bold.Render(info))
	fmt.Println()
}

// Section prints a section header. No-op in quiet mode.
func Section(name string) {
	if !verbose {
		return
	}
	fmt.Println(magenta.Render("  >> ") + bold.Render(name))
}

// Step prints an in-progress step. No-op in quiet mode.
func Step(format string, args ...any) {
	if !verbose {
		return
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Println(subtle.Render("     ") + msg)
}

// OK prints a completed step. No-op in quiet mode.
func OK(format string, args ...any) {
	if !verbose {
		return
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Println(green.Render("  ✓  ") + msg)
}

// Warn prints a warning. Always prints.
func Warn(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	fmt.Println(yellow.Render("  !  ") + msg)
}

// Fail prints an error. Always prints.
func Fail(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintln(os.Stderr, red.Render("  ✗  ")+msg)
}

// Info prints a key-value pair in the ready block.
func Info(key, value string) {
	fmt.Println("  " + keyStyle.Render(key) + valStyle.Render(value))
}

// Ready prints the final ready indicator.
func Ready() {
	fmt.Println()
	fmt.Println(green.Bold(true).Render("  ● ready"))
	fmt.Println()
}

// ReadyWithElapsed prints the ready indicator with elapsed time.
func ReadyWithElapsed(d time.Duration) {
	fmt.Println()
	fmt.Println(green.Bold(true).Render("  ● ready") + subtle.Render(fmt.Sprintf(" (%s)", d)))
	fmt.Println()
}

// Stopped prints the shutdown complete message.
func Stopped() {
	fmt.Println(subtle.Render("  ● stopped"))
}

// Divider prints a thin separator line.
func Divider() {
	fmt.Println(subtle.Render("  " + strings.Repeat("─", 40)))
}

// Shutdown prints the shutdown header.
func Shutdown() {
	fmt.Println()
	if verbose {
		Section("Shutting down")
	}
}

// ProgressLine shows an in-place progress indicator that updates
// with growing dots and elapsed time. Call Done or Fail to finish.
type ProgressLine struct {
	label string
	start time.Time
	mu    sync.Mutex
	done  chan struct{}
}

// Progress starts a progress line that updates in-place.
func Progress(label string) *ProgressLine {
	p := &ProgressLine{
		label: label,
		start: time.Now(),
		done:  make(chan struct{}),
	}
	fmt.Printf("  %s ", label)
	go p.run()
	return p
}

func (p *ProgressLine) run() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-p.done:
			return
		case <-ticker.C:
			elapsed := int(time.Since(p.start).Seconds())
			p.mu.Lock()
			fmt.Printf("\r  %s %s", p.label, subtle.Render(fmt.Sprintf("(%ds)", elapsed)))
			p.mu.Unlock()
		}
	}
}

// Done finishes the progress line with success.
func (p *ProgressLine) Done() {
	close(p.done)
	elapsed := time.Since(p.start).Truncate(time.Second)
	p.mu.Lock()
	// Trailing spaces overwrite leftover dots from the progress updates.
	fmt.Printf("\r  %s %s                              \n", p.label, subtle.Render(fmt.Sprintf("done (%s)", elapsed)))
	p.mu.Unlock()
}

// Fail finishes the progress line with an error.
func (p *ProgressLine) Fail() {
	close(p.done)
	p.mu.Lock()
	fmt.Printf("\r  %s %s                              \n", p.label, red.Render("failed"))
	p.mu.Unlock()
}
