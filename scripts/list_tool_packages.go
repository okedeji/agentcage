package main

import (
	"fmt"
	"sort"

	"github.com/okedeji/agentcage/internal/cagefile"
)

func main() {
	var pkgs []string
	for _, pkg := range cagefile.ToolPackages {
		pkgs = append(pkgs, pkg)
	}
	sort.Strings(pkgs)
	for _, pkg := range pkgs {
		fmt.Println(pkg)
	}
}
