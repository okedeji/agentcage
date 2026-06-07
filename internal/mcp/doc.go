// Package mcp wraps the official Go MCP SDK with a small, agentcage-
// shaped facade.
//
// agentcage talks to every agent over MCP. The protocol surface we
// need is narrow:
//
//   - connect to a process's stdio (the agent inside its container)
//   - list the tools that process exposes
//   - call one of those tools with a typed map of arguments
//   - read the text response back
//
// The wrapper hides three rough edges so callers can stay focused on
// agent orchestration:
//
//  1. Result unwrapping: the SDK's CallToolResult holds a slice of
//     typed content blocks. Most agentcage tools return a single text
//     block; we return that text directly.
//  2. Error wrapping: every error is wrapped with the tool name so
//     downstream logs and CLI messages tell the operator exactly what
//     they tried.
//  3. SDK isolation: if/when the official Go MCP SDK API churns, only
//     this package changes. The rest of agentcage stays put.
//
// This package is the only spot in the repo that imports
// `github.com/modelcontextprotocol/go-sdk/mcp` directly. Resist the
// temptation to import it elsewhere.
package mcp
