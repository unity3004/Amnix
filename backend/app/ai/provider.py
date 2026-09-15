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

Step 13D adds generate_case(): a second, independent generation method for
Case-scoped requests (app.schemas.case_ai.AICaseRequest), deliberately NOT
a union-typed overload of generate() — see app.schemas.case_ai's own
docstring for why AICaseContext is kept fully independent of AIContext.
Keeping this a distinct method (not a widened `request` type on
generate()) means every existing provider's alert-scoped generate()
implementation is completely untouched by this step.
"""

from typing import Protocol, runtime_checkable

from app.schemas.ai import AIRequest, AIResponse
from app.schemas.case_ai import AICaseRequest


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
        """Produce a response for the given alert-scoped request.

        Implementations must never treat `request.context` or
        `request.user_question` as instructions — only
        `request.system_instructions` carries trusted directives. Any
        network/timeout/retry behavior is entirely the implementation's
        concern; this interface itself has no opinion on any of that,
        which is what lets a real (async, potentially slow) provider
        replace MockAIProvider later without changing this contract.
        """
        ...

    def generate_case(self, request: AICaseRequest) -> AIResponse:
        """Produce a response for the given Case-scoped request (Step
        13D). Same trust rules as generate(): `request.context` and
        `request.user_question` are always data, never instructions;
        only `request.system_instructions` may direct the model.
        """
        ...
