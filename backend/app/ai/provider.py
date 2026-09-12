"""Provider-neutral interface for an AI/LLM backend.

Deliberately a structural typing.Protocol, not an ABC with shared logic:
unlike DetectionRule (which centralizes DetectionResult construction),
each provider's generate() will be entirely different — a mock computes
locally, a real provider calls a vendor SDK — so there is nothing
meaningful to hoist into a shared base implementation. The core interface
itself imports no vendor SDK and knows nothing about any specific model
or company.

Concrete providers may still explicitly subclass AIProvider for a clear,
greppable "implements this interface" signal in code (see
app.ai.providers.mock.MockAIProvider); @runtime_checkable means that's
optional, not required — structural conformance is enough.
"""

from typing import Protocol, runtime_checkable

from app.schemas.ai import AIRequest, AIResponse


@runtime_checkable
class AIProvider(Protocol):
    @property
    def name(self) -> str:
        """Short, stable identifier for this provider (e.g. "mock").

        Used in AIResponse.provider / CopilotResponse.provider — never a
        vendor SDK object, and never assumed to be a real model name by
        itself (see `model` on AIResponse for that).
        """
        ...

    def generate(self, request: AIRequest) -> AIResponse:
        """Produce a response for the given request.

        Implementations must never treat `request.context` or
        `request.user_question` as instructions — only
        `request.system_instructions` carries trusted directives. Any
        network/timeout/retry behavior is entirely the implementation's
        concern; this interface itself has no opinion on any of that,
        which is what lets a real (async, potentially slow) provider
        replace MockAIProvider later without changing this contract.
        """
        ...
