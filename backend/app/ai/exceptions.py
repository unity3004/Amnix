"""Application-level errors for the AI Copilot layer."""


class AIProviderError(Exception):
    """Raised when the configured AI provider fails to produce a usable
    response. CopilotService always raises this (or one of its two
    subclasses below — never the underlying provider exception, and
    never a bare AIProviderError directly) so API clients never see raw
    provider error details, stack traces, or potentially sensitive
    diagnostic text. The original exception is chained (`raise ... from
    exc`) and logged server-side for diagnosis. app.api.alerts catches
    this base class and maps it to HTTP 502 — that mapping, and the
    generic message the client receives, are unchanged by the two
    subclasses below; they exist purely so CopilotService itself (for
    Step 10F.4 Copilot-audit outcome classification) can tell two very
    different failure causes apart internally, without either one ever
    becoming a new public exception type.
    """


class AIProviderTransportError(AIProviderError):
    """The provider itself could not be reached, or failed before ever
    producing content to validate: a network/timeout/connection failure,
    an SDK-level exception, an authentication or rate-limit rejection, a
    provider outage, or any other exception raised directly by
    AIProvider.generate(). No AIResponse was ever received, so no model
    name is known either.
    """


class AIProviderValidationError(AIProviderError):
    """The provider DID respond, but AMNIX rejected the response
    content: it didn't parse/validate as the expected schema, it cited a
    fabricated event reference, it named a MITRE technique or
    investigation action outside the application-supplied candidate set,
    or it violated the Step 10E confidence-calibration policy. An
    AIResponse (and therefore a model name) was received before this was
    raised.
    """
