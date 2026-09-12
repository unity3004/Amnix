"""Unit tests for app.ai.factory: the sole provider-construction boundary.

Exercises AI_PROVIDER=mock (still the default, still requires nothing),
AI_PROVIDER=anthropic (with and without ANTHROPIC_API_KEY configured),
and unknown provider values — all via monkeypatched environment variables
plus get_settings.cache_clear(), since Settings is an lru_cache'd
pydantic-settings object. No real network access, no real API key.
"""

import pytest

from app.ai.factory import AnthropicConfigurationError, UnknownAIProviderError, build_ai_provider
from app.ai.providers.anthropic import AnthropicProvider
from app.ai.providers.mock import MockAIProvider
from app.core.config import get_settings


@pytest.fixture(autouse=True)
def _clear_settings_cache():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_default_provider_is_mock_and_requires_no_key(monkeypatch):
    monkeypatch.delenv("AI_PROVIDER", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    get_settings.cache_clear()

    provider = build_ai_provider()

    assert isinstance(provider, MockAIProvider)


def test_explicit_mock_provider_still_works(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "mock")
    get_settings.cache_clear()

    provider = build_ai_provider()

    assert isinstance(provider, MockAIProvider)
    assert provider.name == "mock"


def test_anthropic_provider_constructed_when_api_key_present(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-not-real")
    monkeypatch.setenv("ANTHROPIC_MODEL", "claude-sonnet-5")
    monkeypatch.setenv("ANTHROPIC_MAX_TOKENS", "256")
    monkeypatch.setenv("ANTHROPIC_TIMEOUT_SECONDS", "10")
    get_settings.cache_clear()

    provider = build_ai_provider()

    assert isinstance(provider, AnthropicProvider)
    assert provider.name == "anthropic"
    assert provider._model == "claude-sonnet-5"
    assert provider._max_tokens == 256
    assert provider._timeout_seconds == 10.0


def test_anthropic_provider_fails_clearly_when_api_key_missing(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "anthropic")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    get_settings.cache_clear()

    with pytest.raises(AnthropicConfigurationError):
        build_ai_provider()


def test_missing_api_key_error_does_not_silently_fall_back_to_mock(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "anthropic")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    get_settings.cache_clear()

    try:
        provider = build_ai_provider()
    except AnthropicConfigurationError:
        provider = None

    assert provider is None  # never silently substitutes MockAIProvider


def test_unknown_provider_fails_clearly(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "some-other-vendor")
    get_settings.cache_clear()

    with pytest.raises(UnknownAIProviderError):
        build_ai_provider()


def test_provider_name_argument_overrides_settings(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "mock")
    get_settings.cache_clear()

    with pytest.raises(UnknownAIProviderError):
        build_ai_provider("totally-unknown")


def test_unknown_provider_error_message_does_not_leak_secrets(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "bogus")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-should-never-appear")
    get_settings.cache_clear()

    with pytest.raises(UnknownAIProviderError) as exc_info:
        build_ai_provider()

    assert "sk-ant-should-never-appear" not in str(exc_info.value)
