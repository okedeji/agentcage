package ui

import (
	"fmt"
	"os"
	"strings"

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

// Section prints a section header for a boot phase.
func Section(name string) {
	fmt.Println(magenta.Render("  >> ") + bold.Render(name))
}

// Step prints an in-progress step within a section.
func Step(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	fmt.Println(subtle.Render("     ") + msg)
}

// OK prints a completed step.
func OK(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	fmt.Println(green.Render("  ✓  ") + msg)
}

// Warn prints a warning.
func Warn(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	fmt.Println(yellow.Render("  !  ") + msg)
}

// Fail prints an error.
func Fail(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintln(os.Stderr, red.Render("  ✗  ")+msg)
}

// Info prints a key-value pair in the ready banner.
func Info(key, value string) {
	fmt.Println("     " + keyStyle.Render(key) + valStyle.Render(value))
}

// Ready prints the final ready banner.
func Ready() {
	fmt.Println()
	fmt.Println(green.Bold(true).Render("  ● ready"))
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
	Section("Shutting down")
}
