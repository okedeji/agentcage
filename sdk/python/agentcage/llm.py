"""LLM helpers.

Two entry points serve two different needs.

complete() is the convenience: one user message in, one text response
out. Provider chosen by model name. Good for getting-started agents,
tool collections that need a single LLM call, and any case where the
shape of "ask, receive" is enough.

    text = agentcage.llm.complete(user="Hi", system="You are concise.")

anthropic_client() and openai_client() return a preconfigured native
SDK client when more is needed: multi-turn conversations, tool use,
streaming, vision, structured outputs, any provider feature outside
the simple ask-receive case.

    client = agentcage.llm.anthropic_client()
    # full Anthropic API from here

The provider for complete() comes from the model name in
"provider/model-name" form, matching the Agentfile's MODEL directive:
"anthropic/claude-3-5-sonnet" or "openai/gpt-4o". Supported providers
are anthropic and openai.

Model resolution order for complete():

    1. The model= keyword argument when passed explicitly.
    2. The AGENTCAGE_MODEL environment variable, set by the runtime
       from the MODEL directive.
    3. Otherwise, RuntimeError.

Credentials:

    Anthropic reads ANTHROPIC_API_KEY. The runtime injects it when the
        Agentfile declares SECRETS anthropic_api_key.
    OpenAI reads OPENAI_API_KEY. The runtime injects it when the
        Agentfile declares SECRETS openai_api_key.
"""

from __future__ import annotations

import os
from typing import Optional

from anthropic import Anthropic
from openai import OpenAI

DEFAULT_MAX_TOKENS = 1024

_anthropic_client: Optional[Anthropic] = None
_openai_client: Optional[OpenAI] = None


def complete(
    user: str | None = None,
    *,
    messages: list[dict] | None = None,
    system: str = "",
    model: str | None = None,
    max_tokens: int = DEFAULT_MAX_TOKENS,
) -> str:
    """Issue a chat completion and return the response text.

    Two call shapes are accepted:

        # Single-turn: pass `user` (and optionally `system`).
        complete(user="Hi", system="You are concise.")

        # Multi-turn: pass the full `messages` array (the same shape
        # OpenAI and Anthropic accept).
        complete(messages=[
            {"role": "system",    "content": "You are concise."},
            {"role": "user",      "content": "Hi"},
            {"role": "assistant", "content": "Hello!"},
            {"role": "user",      "content": "What's my name?"},
        ])

    When both `messages` and `user` are passed, `messages` wins. If the
    `system` keyword is set and the messages list does not already
    contain a system message, one is prepended.

    For richer flows (tool use, streaming, vision, structured outputs,
    multimodal blocks) drop to the native SDK via anthropic_client() or
    openai_client().

    Args:
        user: A single user message. Shortcut for messages=[{role:user,
            content:<user>}].
        messages: A list of {role, content} dicts. Roles: system, user,
            assistant. Same shape both providers accept.
        system: Optional system prompt. Folded into messages.
        model: "provider/model-name" (e.g. "anthropic/claude-3-5-sonnet").
            When omitted, AGENTCAGE_MODEL is read from the environment.
        max_tokens: Cap on the response length. Defaults to 1024.

    Returns:
        The text content of the model's response. Empty string when no
        text block is present.

    Raises:
        ValueError: neither `user` nor `messages` was passed.
        RuntimeError: model is missing or malformed, provider is unknown,
            or the required API key env var is not set.
    """
    resolved_messages = _normalize_messages(user=user, messages=messages, system=system)
    resolved = _resolve_model(model)
    provider, model_name = _split_provider(resolved)
    return _dispatch(provider, model_name, resolved_messages, max_tokens)


def _normalize_messages(
    *, user: str | None, messages: list[dict] | None, system: str
) -> list[dict]:
    """Reduce the two call shapes (single `user` vs `messages` array)
    into one canonical messages list. Adds the `system` prefix when
    one is set and not already present."""
    if messages is None and user is None:
        raise ValueError("complete() requires either user= or messages=")
    if messages is None:
        messages = [{"role": "user", "content": user}]
    if system and not any(m.get("role") == "system" for m in messages):
        messages = [{"role": "system", "content": system}, *messages]
    return messages


def reset_client() -> None:
    """Drop cached clients. Useful in tests that mock the LLM SDKs."""
    global _anthropic_client, _openai_client
    _anthropic_client = None
    _openai_client = None


def _resolve_model(model: str | None) -> str:
    if model:
        return model
    env_model = os.environ.get("AGENTCAGE_MODEL", "")
    if env_model:
        return env_model
    raise RuntimeError(
        "no model specified and AGENTCAGE_MODEL is not set. "
        "Pass model='provider/name' explicitly, or run via the runtime "
        "which injects AGENTCAGE_MODEL from the Agentfile's MODEL directive."
    )


def _split_provider(model: str) -> tuple[str, str]:
    if "/" not in model:
        raise RuntimeError(
            f"model {model!r} is not 'provider/model-name' (expected "
            f"something like 'anthropic/claude-3-5-sonnet')."
        )
    provider, name = model.split("/", 1)
    if not provider or not name:
        raise RuntimeError(
            f"model {model!r} is not 'provider/model-name' (provider or "
            f"model name is empty)."
        )
    return provider, name


def _dispatch(provider: str, model: str, messages: list[dict], max_tokens: int) -> str:
    if provider == "anthropic":
        return _complete_anthropic(messages, model, max_tokens)
    if provider == "openai":
        return _complete_openai(messages, model, max_tokens)
    raise RuntimeError(
        f"unknown provider {provider!r} (supported: anthropic, openai)."
    )


def _complete_anthropic(messages: list[dict], model: str, max_tokens: int) -> str:
    # Anthropic's messages API takes system as a separate parameter
    # and only accepts user/assistant turns in the messages list. Split
    # them apart before sending.
    system_parts: list[str] = []
    chat_messages: list[dict] = []
    for msg in messages:
        if msg.get("role") == "system":
            content = msg.get("content", "")
            if content:
                system_parts.append(content)
        else:
            chat_messages.append(msg)

    client = anthropic_client()
    kwargs: dict = {
        "model": model,
        "max_tokens": max_tokens,
        "messages": chat_messages,
    }
    if system_parts:
        kwargs["system"] = "\n\n".join(system_parts)
    response = client.messages.create(**kwargs)
    for block in response.content:
        if getattr(block, "type", None) == "text":
            return block.text
    return ""


def _complete_openai(messages: list[dict], model: str, max_tokens: int) -> str:
    # OpenAI's chat.completions endpoint takes the full messages list
    # including system turns. Pass through as-is.
    client = openai_client()
    response = client.chat.completions.create(
        model=model,
        max_tokens=max_tokens,
        messages=messages,
    )
    return response.choices[0].message.content or ""


def anthropic_client() -> Anthropic:
    """Return a preconfigured Anthropic client.

    The client reads its API key from ANTHROPIC_API_KEY, which the
    runtime injects when the Agentfile declares
    `SECRETS anthropic_api_key`. The same client is reused across calls
    so it shares a connection pool.

    Use this for anything beyond complete()'s single-turn text-only
    case: multi-turn conversations, tool use, streaming, vision,
    structured outputs, or any other Anthropic API feature.

    Raises:
        RuntimeError: ANTHROPIC_API_KEY is not set.
    """
    global _anthropic_client
    if _anthropic_client is None:
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY is not set. Add 'SECRETS anthropic_api_key' "
                "to the Agentfile so the runtime injects it."
            )
        _anthropic_client = Anthropic(api_key=api_key)
    return _anthropic_client


def openai_client() -> OpenAI:
    """Return a preconfigured OpenAI client.

    The client reads its API key from OPENAI_API_KEY, which the runtime
    injects when the Agentfile declares `SECRETS openai_api_key`. The
    same client is reused across calls so it shares a connection pool.

    Use this for anything beyond complete()'s single-turn text-only
    case: multi-turn conversations, tool use, streaming, vision,
    structured outputs, assistants, or any other OpenAI API feature.

    Raises:
        RuntimeError: OPENAI_API_KEY is not set.
    """
    global _openai_client
    if _openai_client is None:
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError(
                "OPENAI_API_KEY is not set. Add 'SECRETS openai_api_key' "
                "to the Agentfile so the runtime injects it."
            )
        _openai_client = OpenAI(api_key=api_key)
    return _openai_client
