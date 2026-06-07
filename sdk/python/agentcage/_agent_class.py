"""The Agent class — a thin wrapper around FastMCP that mirrors the
Agentfile's MAIN and EXPOSE directives in Python sugar.

The Agentfile is the platform contract. These decorators do not enforce
anything at runtime; they exist so author code reads symmetrically with
the Agentfile and so future tooling (build-time introspection,
`agentcage sync`'s type stubs) can pick up the marks.
"""

from __future__ import annotations

from typing import Callable, Set

from mcp.server.fastmcp import FastMCP


class Agent(FastMCP):
    """An MCP server with agentcage-shaped decorators.

    Use `@agent.main()` on the tool that runs when callers invoke the
    agent as an agent (`agentcage run BUNDLE "..."`). Use
    `@agent.tool(expose=True)` for tools that should be callable from
    outside the cage (`agentcage call BUNDLE TOOL --arg ...`). Use
    `@agent.tool()` for tools that should only be reachable from
    within the agent's own reasoning loop.

    Pair every decorator with its Agentfile counterpart (`MAIN`,
    `EXPOSE`). The Agentfile is what the platform reads; these
    decorators are sugar.
    """

    def __init__(self, name: str, instructions: str | None = None, **kwargs):
        super().__init__(name, instructions=instructions, **kwargs)
        self._main_tool_name: str | None = None
        self._exposed_tool_names: Set[str] = set()

    def main(self, name: str | None = None, description: str | None = None, **kwargs):
        """Decorator marking a tool as the agent's reasoning entry.

        Equivalent to `@tool()` plus a record that this is the agent's
        MAIN. At most one `@main()` per agent is meaningful; later
        ones overwrite the recorded name.
        """
        inner = self.tool(name=name, description=description, **kwargs)

        def decorator(fn: Callable) -> Callable:
            wrapped = inner(fn)
            self._main_tool_name = name or fn.__name__
            return wrapped

        return decorator

    def tool(self, *args, expose: bool = False, **kwargs):
        """Decorator that registers a tool. Pass `expose=True` to mark
        it as publicly callable from outside the cage; mirror with an
        `EXPOSE` directive in the Agentfile.

        Without `expose=True`, the tool is private — only reachable
        from within the agent's own reasoning (the function body of
        whatever `@main()` decorated).
        """
        inner = super().tool(*args, **kwargs)

        def decorator(fn: Callable) -> Callable:
            tool_name = kwargs.get("name") or fn.__name__
            if expose:
                self._exposed_tool_names.add(tool_name)
            return inner(fn)

        return decorator
