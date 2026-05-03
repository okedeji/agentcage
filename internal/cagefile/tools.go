package cagefile

// ToolPackages maps each supported tool to its Alpine package name.
// Single source of truth: the cage rootfs build script reads this
// list to know what to pre-install.
var ToolPackages = map[string]string{
	"chromium":   "chromium",
	"nmap":       "nmap",
	"sqlmap":     "sqlmap",
	"ffuf":       "ffuf",
	"curl":       "curl",
	"wget":       "wget",
	"jq":         "jq",
	"bind-tools": "bind-tools",
	"interactsh": "interactsh",  // GitHub release binary, not Alpine
	"nuclei":     "nuclei",      // GitHub release binary, not Alpine
	"subfinder":  "subfinder",   // GitHub release binary, not Alpine
	"httpx":      "httpx",       // GitHub release binary, not Alpine
	"katana":     "katana",      // GitHub release binary, not Alpine
}
