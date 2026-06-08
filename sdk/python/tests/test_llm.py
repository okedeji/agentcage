"""Tests for agentcage.llm dispatch and provider wrappers."""

from unittest.mock import MagicMock, patch

import pytest

from agentcage import llm


@pytest.fixture(autouse=True)
def _reset_clients(monkeypatch):
    """Reset cached clients and provide test API keys around each test."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-anthropic-key")
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")
    monkeypatch.delenv("AGENTCAGE_MODEL", raising=False)
    llm.reset_client()
    yield
    llm.reset_client()


def _anthropic_response(text: str):
    block = MagicMock()
    block.type = "text"
    block.text = text
    response = MagicMock()
    response.content = [block]
    return response


def _openai_response(text: str):
    choice = MagicMock()
    choice.message.content = text
    response = MagicMock()
    response.choices = [choice]
    return response


# ----- Dispatch: model resolution and provider selection ------------------


def test_explicit_model_routes_to_anthropic():
    fake = MagicMock()
    fake.messages.create.return_value = _anthropic_response("hi from claude")
    with patch("agentcage.llm.Anthropic", return_value=fake):
        result = llm.complete(user="Hi", model="anthropic/claude-3-5-sonnet")
    assert result == "hi from claude"
    assert fake.messages.create.call_args.kwargs["model"] == "claude-3-5-sonnet"


def test_explicit_model_routes_to_openai():
    fake = MagicMock()
    fake.chat.completions.create.return_value = _openai_response("hi from gpt")
    with patch("agentcage.llm.OpenAI", return_value=fake):
        result = llm.complete(user="Hi", model="openai/gpt-4o")
    assert result == "hi from gpt"
    assert fake.chat.completions.create.call_args.kwargs["model"] == "gpt-4o"


def test_model_resolved_from_env_when_omitted(monkeypatch):
    monkeypatch.setenv("AGENTCAGE_MODEL", "anthropic/claude-3-5-sonnet")
    fake = MagicMock()
    fake.messages.create.return_value = _anthropic_response("from env")
    with patch("agentcage.llm.Anthropic", return_value=fake):
        assert llm.complete(user="Hi") == "from env"


def test_raises_when_model_missing_everywhere():
    with pytest.raises(RuntimeError, match="AGENTCAGE_MODEL"):
        llm.complete(user="Hi")


def test_raises_on_malformed_model():
    with pytest.raises(RuntimeError, match="provider/model-name"):
        llm.complete(user="Hi", model="just-a-name")


def test_raises_on_unknown_provider():
    with pytest.raises(RuntimeError, match="unknown provider"):
        llm.complete(user="Hi", model="google/gemini")


# ----- Anthropic wrapper specifics ---------------------------------------


def test_anthropic_passes_system_when_provided():
    fake = MagicMock()
    fake.messages.create.return_value = _anthropic_response("ok")
    with patch("agentcage.llm.Anthropic", return_value=fake):
        llm.complete(user="Hi", system="You are friendly.", model="anthropic/x")
    assert fake.messages.create.call_args.kwargs["system"] == "You are friendly."


def test_anthropic_omits_system_when_empty():
    fake = MagicMock()
    fake.messages.create.return_value = _anthropic_response("ok")
    with patch("agentcage.llm.Anthropic", return_value=fake):
        llm.complete(user="Hi", model="anthropic/x")
    assert "system" not in fake.messages.create.call_args.kwargs


def test_anthropic_returns_empty_when_no_text_block():
    fake = MagicMock()
    response = MagicMock()
    response.content = []
    fake.messages.create.return_value = response
    with patch("agentcage.llm.Anthropic", return_value=fake):
        assert llm.complete(user="Hi", model="anthropic/x") == ""


def test_anthropic_raises_without_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    llm.reset_client()
    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
        llm.complete(user="Hi", model="anthropic/x")


# ----- OpenAI wrapper specifics -----------------------------------------


def test_openai_includes_system_as_first_message():
    fake = MagicMock()
    fake.chat.completions.create.return_value = _openai_response("ok")
    with patch("agentcage.llm.OpenAI", return_value=fake):
        llm.complete(user="Hi", system="You are friendly.", model="openai/x")
    messages = fake.chat.completions.create.call_args.kwargs["messages"]
    assert messages[0] == {"role": "system", "content": "You are friendly."}
    assert messages[1] == {"role": "user", "content": "Hi"}


def test_openai_omits_system_when_empty():
    fake = MagicMock()
    fake.chat.completions.create.return_value = _openai_response("ok")
    with patch("agentcage.llm.OpenAI", return_value=fake):
        llm.complete(user="Hi", model="openai/x")
    messages = fake.chat.completions.create.call_args.kwargs["messages"]
    assert messages == [{"role": "user", "content": "Hi"}]


def test_openai_returns_empty_when_content_is_none():
    fake = MagicMock()
    choice = MagicMock()
    choice.message.content = None
    response = MagicMock()
    response.choices = [choice]
    fake.chat.completions.create.return_value = response
    with patch("agentcage.llm.OpenAI", return_value=fake):
        assert llm.complete(user="Hi", model="openai/x") == ""


# ----- Multi-turn messages parameter -------------------------------------

# The platform does not store conversation history; the caller passes
# the full {role, content} array and the agent forwards it to complete().
# These tests pin the contract: messages= must work with both providers
# and across the user/system folding rules.


def test_messages_routes_to_anthropic_with_system_split_out():
    fake = MagicMock()
    fake.messages.create.return_value = _anthropic_response("multi-turn anthropic")
    msgs = [
        {"role": "system", "content": "You are concise."},
        {"role": "user", "content": "Hi"},
        {"role": "assistant", "content": "Hello!"},
        {"role": "user", "content": "What's my name?"},
    ]
    with patch("agentcage.llm.Anthropic", return_value=fake):
        result = llm.complete(messages=msgs, model="anthropic/x")
    assert result == "multi-turn anthropic"
    kwargs = fake.messages.create.call_args.kwargs
    # Anthropic puts system in its own param, not in the messages list.
    assert kwargs["system"] == "You are concise."
    assert kwargs["messages"] == msgs[1:]


def test_messages_routes_to_openai_with_system_inline():
    fake = MagicMock()
    fake.chat.completions.create.return_value = _openai_response("multi-turn openai")
    msgs = [
        {"role": "system", "content": "You are concise."},
        {"role": "user", "content": "Hi"},
        {"role": "assistant", "content": "Hello!"},
        {"role": "user", "content": "What's my name?"},
    ]
    with patch("agentcage.llm.OpenAI", return_value=fake):
        result = llm.complete(messages=msgs, model="openai/x")
    assert result == "multi-turn openai"
    # OpenAI keeps system in the messages list.
    assert fake.chat.completions.create.call_args.kwargs["messages"] == msgs


def test_messages_with_system_kwarg_prepends_when_no_system_role_present():
    fake = MagicMock()
    fake.messages.create.return_value = _anthropic_response("ok")
    with patch("agentcage.llm.Anthropic", return_value=fake):
        llm.complete(
            messages=[{"role": "user", "content": "Hi"}],
            system="You are concise.",
            model="anthropic/x",
        )
    assert fake.messages.create.call_args.kwargs["system"] == "You are concise."


def test_messages_with_system_kwarg_does_not_override_existing_system_role():
    fake = MagicMock()
    fake.messages.create.return_value = _anthropic_response("ok")
    with patch("agentcage.llm.Anthropic", return_value=fake):
        llm.complete(
            messages=[
                {"role": "system", "content": "From messages."},
                {"role": "user", "content": "Hi"},
            ],
            system="From kwarg.",
            model="anthropic/x",
        )
    assert fake.messages.create.call_args.kwargs["system"] == "From messages."


def test_messages_wins_when_both_user_and_messages_passed():
    fake = MagicMock()
    fake.chat.completions.create.return_value = _openai_response("ok")
    with patch("agentcage.llm.OpenAI", return_value=fake):
        llm.complete(
            user="ignored",
            messages=[{"role": "user", "content": "from messages"}],
            model="openai/x",
        )
    sent = fake.chat.completions.create.call_args.kwargs["messages"]
    assert sent == [{"role": "user", "content": "from messages"}]


def test_complete_rejects_call_with_neither_user_nor_messages():
    with pytest.raises(ValueError, match="user= or messages="):
        llm.complete(model="anthropic/x")


def test_anthropic_concatenates_multiple_system_messages():
    fake = MagicMock()
    fake.messages.create.return_value = _anthropic_response("ok")
    with patch("agentcage.llm.Anthropic", return_value=fake):
        llm.complete(
            messages=[
                {"role": "system", "content": "Be concise."},
                {"role": "system", "content": "And friendly."},
                {"role": "user", "content": "Hi"},
            ],
            model="anthropic/x",
        )
    assert fake.messages.create.call_args.kwargs["system"] == "Be concise.\n\nAnd friendly."


def test_openai_raises_without_api_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    llm.reset_client()
    with pytest.raises(RuntimeError, match="OPENAI_API_KEY"):
        llm.complete(user="Hi", model="openai/x")


# ----- Public client helpers ---------------------------------------------


def test_anthropic_client_returns_configured_client():
    sentinel = object()
    with patch("agentcage.llm.Anthropic", return_value=sentinel) as ctor:
        got = llm.anthropic_client()
    assert got is sentinel
    assert ctor.call_args.kwargs["api_key"] == "test-anthropic-key"


def test_anthropic_client_is_cached_across_calls():
    """Repeated calls reuse the same client instance (connection pool sharing)."""
    sentinel = object()
    with patch("agentcage.llm.Anthropic", return_value=sentinel) as ctor:
        first = llm.anthropic_client()
        second = llm.anthropic_client()
    assert first is second
    assert ctor.call_count == 1


def test_anthropic_client_raises_without_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    llm.reset_client()
    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
        llm.anthropic_client()


def test_openai_client_returns_configured_client():
    sentinel = object()
    with patch("agentcage.llm.OpenAI", return_value=sentinel) as ctor:
        got = llm.openai_client()
    assert got is sentinel
    assert ctor.call_args.kwargs["api_key"] == "test-openai-key"


def test_openai_client_is_cached_across_calls():
    sentinel = object()
    with patch("agentcage.llm.OpenAI", return_value=sentinel) as ctor:
        first = llm.openai_client()
        second = llm.openai_client()
    assert first is second
    assert ctor.call_count == 1


def test_openai_client_raises_without_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    llm.reset_client()
    with pytest.raises(RuntimeError, match="OPENAI_API_KEY"):
        llm.openai_client()
