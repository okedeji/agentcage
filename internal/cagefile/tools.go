package cagefile

// ToolPackages maps each supported tool to its Alpine package name.
// This is the single source of truth — the cage rootfs build script
// reads this list to know what to pre-install.
var ToolPackages = map[string]string{
	"chromium":   "chromium",
	"nmap":       "nmap",
	"sqlmap":     "sqlmap",
	"nikto":      "nikto",
	"ffuf":       "ffuf",
	"interactsh": "interactsh",
	"curl":       "curl",
	"wget":       "wget",
}
