"""The provider construction boundary.

This is the ONLY place that maps AI_PROVIDER configuration to a concrete
AIProvider instance. CopilotService never instantiates a provider itself
— it only ever receives one through its constructor (see
app.services.copilot_service and the get_copilot_service FastAPI
dependency in app.api.alerts). Adding a real provider later means adding
one branch here and a new module under app.ai.providers — nothing in
CopilotService, the API layer, or the existing test suite needs to change.
"""

from functools import lru_cache

from app.ai.provider import AIProvider
from app.ai.providers.anthropic import AnthropicProvider
from app.ai.providers.mock import MockAIProvider
from app.core.config import get_settings


class UnknownAIProviderError(ValueError):
    def __init__(self, provider_name: str) -> None:
        self.provider_name = provider_name
        super().__init__(f"Unknown AI_PROVIDER '{provider_name}'")


class AnthropicConfigurationError(ValueError):
    """Raised when AI_PROVIDER=anthropic is configured but required
    Anthropic-specific configuration (currently: ANTHROPIC_API_KEY) is
    missing. Raised here, at provider-construction time, so a
    misconfigured "anthropic" choice fails fast and loudly — AMNIX never
    silently substitutes MockAIProvider for an explicitly-configured real
    provider.
    """


def build_ai_provider(provider_name: str | None = None) -> AIProvider:
    """Construct a provider by name (defaulting to the configured
    AI_PROVIDER). Kept separate from the cached get_ai_provider() below
    so tests can construct arbitrary named providers without touching
    global config/cache state.
    """
    settings = get_settings()
    name = (provider_name if provider_name is not None else settings.ai_provider).strip().lower()
    if name == "mock":
        return MockAIProvider()
    if name == "anthropic":
        if not settings.anthropic_api_key:
            raise AnthropicConfigurationError(
                "AI_PROVIDER=anthropic requires ANTHROPIC_API_KEY to be set."
            )
        return AnthropicProvider(
            api_key=settings.anthropic_api_key,
            model=settings.anthropic_model,
            max_tokens=settings.anthropic_max_tokens,
            timeout_seconds=settings.anthropic_timeout_seconds,
        )
    raise UnknownAIProviderError(name)


@lru_cache
def get_ai_provider() -> AIProvider:
    """FastAPI-dependency-friendly cached provider instance, built from
    the configured AI_PROVIDER. Cached for the same reason get_settings()
    is: a provider (even a stateless mock, and especially a future real
    one holding an HTTP client) should be constructed once per process,
    not once per request.
    """
    return build_ai_provider()
