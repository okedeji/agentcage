//go:build linux

package main

func platformInit(args []string) {
	cmdInit(args)
}

func platformStop(args []string) {
	cmdStop(args)
}

func isProxyCommand(_ string) bool {
	return false
}
