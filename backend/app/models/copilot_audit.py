"""CopilotAudit: an append-only audit trail row for one AI Copilot
invocation (see app.services.copilot_service.ask() / .follow_up()).

Step 10F.2 — persistence/data-model layer ONLY. Nothing in this file (or
anywhere else as of this step) writes a CopilotAudit row yet:
CopilotService is not touched, no API endpoint exists, and there is no
retrieval path. That wiring is Step 10F.3+.

Deliberately excluded from this model (do not add these later without
re-opening the security review that produced this list):
  - system_instructions (trusted, code-only prompt text — logging it
    would be redundant and would tie audit rows to a specific prompt
    version's exact wording for no investigative benefit)
  - the raw AIContext, or any raw SecurityEvent data — this table audits
    THAT a call happened, not a replay of what was sent
  - the complete user question, conversation history, or generated AI
    response/assessment — see `question_fingerprint` below for how a
    request is still identifiable without storing its content
  - raw database UUIDs as they appear inside AI-facing payloads (the
    `evt-N` synthetic event_ref scheme) — not applicable here since this
    table stores no AI-facing payload at all
  - API keys/secrets of any kind
  - raw provider exceptions/tracebacks — CopilotService already refuses
    to leak provider exception details past its own AIProviderError
    wrapper (see copilot_service.py's `_generate`); this table does not
    reintroduce a path for that text to end up somewhere persisted

Traceability without content: `question_fingerprint` is a SHA-256 hex
digest computed by the caller (Step 10F.3) over the request's
identifying text (the question, and for follow_up, question+history) —
enough to notice "this exact request happened before" or correlate
support tickets to a specific invocation, without this table ever
holding the prompt itself. `question_length`/`history_turn_count` are
bounded, content-free size metadata for the same reason.

Three distinct outcome axes, not one: `outcome` (success/failure),
`validation_status` (passed/failed/not_applicable), and `http_status`
(the code app.api.alerts actually returned) look redundant under
CopilotService's CURRENT two-outcome shape (every call today either
fully succeeds -> 200/success/passed, or raises AIProviderError ->
502/failure/{failed or not_applicable}) — and a CHECK constraint below
enforces exactly that correlation for now. They are kept separate
because they answer different investigative questions once the system
grows: `validation_status` alone can already distinguish "the provider
transport failed (timeout/auth/rate-limit) before validation ever ran"
(not_applicable) from "the provider responded but AMNIX rejected the
content" (failed) — the single most useful signal for deciding whether
a spike in failures is Anthropic's availability or a prompt-adherence
regression. `http_status` is kept explicit (rather than derived) because
it is what the analyst-facing client actually observed.

alert_id uses ondelete="CASCADE": an audit row has no independent
meaning once its Alert is gone, exactly the same reasoning
alert_security_events.alert_id already uses (see app.models.alert).
AMNIX has no alert-delete endpoint today, so this is currently inert —
noted here for whoever adds one later.

Append-only, like SecurityEvent: an audit row records a fact about a
past invocation, so there is no `updated_at` and no update path.

Step 13D — Case-scoped Copilot audit rows (migration required, discovery
and smallest-safe-extension approved via the Step 13D gate report):
`alert_id` becomes NULLABLE and a new nullable `case_id` (FK to
`cases.id`, `ondelete="CASCADE"`, same reasoning as `alert_id`) is added.
A row is EITHER alert-scoped (app.services.copilot_service.ask()/
follow_up()) OR case-scoped (app.services.case_copilot_service.
ask_about_case()) — never both, never neither: `ck_copilot_audits_exactly_one_scope`
enforces "exactly one of alert_id/case_id is set" at the database level,
the same "closed, mutually exclusive scope" pattern app.models.case_audit's
own `ck_case_audits_related_alert_id_matches_action` already established
for a structurally identical problem (a column that is required for some
actions and forbidden for others). This is deliberately NOT a polymorphic
`scope_type`/`scope_id` pair (the brief's own alternative suggestion): two
real, independently-FK-constrained nullable columns let Postgres itself
enforce referential integrity for whichever one is set, which a single
untyped `scope_id` column could not.
`request_type` gains a third value, 'case_brief' — the Case-scoped
counterpart to 'ask' — which, like 'ask', never carries conversation
history.

Step 13E adds a fourth value, 'case_follow_up' — the Case-scoped
counterpart to 'follow_up' — which, like 'follow_up', always carries a
(possibly empty) conversation_history list. This required widening
`ck_copilot_audits_request_type_valid` and
`ck_copilot_audits_history_turn_count_only_for_follow_up` a second time
(see the Step 13D migration for the first widening) — an additive-only
change, exactly the same drop+recreate-CHECK-constraint pattern.
"""

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, SmallInteger, String, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.alert import Alert
from app.models.case import Case


class CopilotAudit(Base):
    """One audit row per app.services.copilot_service.ask()/follow_up()
    OR app.services.case_copilot_service.ask_about_case() invocation. See
    this module's docstring for the full field rationale and the list of
    things deliberately never persisted here.
    """

    __tablename__ = "copilot_audits"
    __table_args__ = (
        Index("ix_copilot_audits_alert_id", "alert_id"),
        Index("ix_copilot_audits_case_id", "case_id"),
        Index("ix_copilot_audits_created_at", "created_at"),
        CheckConstraint(
            "request_type IN ('ask', 'follow_up', 'case_brief', 'case_follow_up')",
            name="ck_copilot_audits_request_type_valid",
        ),
        CheckConstraint(
            "(alert_id IS NOT NULL AND case_id IS NULL) OR (alert_id IS NULL AND case_id IS NOT NULL)",
            name="ck_copilot_audits_exactly_one_scope",
        ),
        CheckConstraint("outcome IN ('success', 'failure')", name="ck_copilot_audits_outcome_valid"),
        CheckConstraint(
            "validation_status IN ('passed', 'failed', 'not_applicable')",
            name="ck_copilot_audits_validation_status_valid",
        ),
        CheckConstraint("http_status IN (200, 502)", name="ck_copilot_audits_http_status_valid"),
        CheckConstraint("length(btrim(provider_name)) > 0", name="ck_copilot_audits_provider_name_not_blank"),
        CheckConstraint(
            "model_name IS NULL OR length(btrim(model_name)) > 0",
            name="ck_copilot_audits_model_name_not_blank",
        ),
        # SHA-256 hex digest: always exactly 64 lowercase hex characters.
        # Enforcing the shape here (not just NOT NULL) makes it impossible
        # to accidentally persist raw question text through this column —
        # anything that isn't a well-formed hex digest is rejected by the
        # database itself, not just by application-layer discipline.
        CheckConstraint(
            "question_fingerprint ~ '^[0-9a-f]{64}$'",
            name="ck_copilot_audits_question_fingerprint_sha256_hex",
        ),
        CheckConstraint("question_length >= 0", name="ck_copilot_audits_question_length_non_negative"),
        CheckConstraint(
            "history_turn_count IS NULL OR history_turn_count >= 0",
            name="ck_copilot_audits_history_turn_count_non_negative",
        ),
        CheckConstraint("duration_ms IS NULL OR duration_ms >= 0", name="ck_copilot_audits_duration_ms_non_negative"),
        # An initial ask() has no conversation history at all (see
        # AIRequest's None-vs-list mode discriminator), and neither does
        # case_brief (AICaseRequest.conversation_history is None for that
        # call — see app.schemas.case_ai's own docstring) —
        # history_turn_count must be NULL for both 'ask' and 'case_brief'
        # rows, and is free to be NULL (no prior turns) or >= 0 for
        # 'follow_up' and (Step 13E) 'case_follow_up' rows, both of which
        # always carry a (possibly empty) conversation_history list.
        CheckConstraint(
            "(request_type IN ('ask', 'case_brief') AND history_turn_count IS NULL) "
            "OR (request_type IN ('follow_up', 'case_follow_up'))",
            name="ck_copilot_audits_history_turn_count_only_for_follow_up",
        ),
        # Ties the three outcome axes together for CopilotService's
        # current two-outcome shape (see module docstring) — deliberately
        # strict so any future third outcome forces a conscious migration
        # rather than silently drifting the axes out of sync.
        CheckConstraint(
            "(outcome = 'success' AND http_status = 200 AND validation_status = 'passed') OR "
            "(outcome = 'failure' AND http_status = 502 AND validation_status IN ('failed', 'not_applicable'))",
            name="ck_copilot_audits_outcome_http_validation_consistency",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )

    # Exactly one of alert_id/case_id is set — see this module's own
    # Step 13D docstring section and ck_copilot_audits_exactly_one_scope.
    alert_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=True
    )
    case_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=True
    )

    # 'ask' == CopilotService.ask() (initial structured assessment),
    # 'follow_up' == CopilotService.follow_up() (alert-scoped follow-up
    # conversation), 'case_brief' == CaseCopilotService.ask_about_case()
    # (Step 13D, Case-scoped investigation brief), 'case_follow_up' ==
    # CaseCopilotService.ask_case_follow_up() (Step 13E, Case-scoped
    # follow-up conversation) — see app.services.copilot_service /
    # app.services.case_copilot_service.
    request_type: Mapped[str] = mapped_column(String(20), nullable=False)

    # Open vocabulary by design (matches AIProvider.name / the model
    # name a provider reports) — new providers/models must not require a
    # migration, so these are bounded strings with a not-blank CHECK
    # rather than a fixed enum. model_name is nullable: it is only known
    # once a provider response comes back, and a transport-level failure
    # (timeout, auth, rate limit) may occur before that.
    provider_name: Mapped[str] = mapped_column(String(50), nullable=False)
    model_name: Mapped[str | None] = mapped_column(String(200), nullable=True)

    outcome: Mapped[str] = mapped_column(String(10), nullable=False)
    validation_status: Mapped[str] = mapped_column(String(20), nullable=False)
    http_status: Mapped[int] = mapped_column(SmallInteger, nullable=False)

    # SHA-256 hex digest of the request's identifying text — see module
    # docstring. question_length/history_turn_count are content-free size
    # metadata, never the content itself.
    question_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    question_length: Mapped[int] = mapped_column(Integer, nullable=False)
    history_turn_count: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Milliseconds. No pre-existing project convention for persisted
    # timing exists (AnthropicProvider only logs duration, never stores
    # it) — this is a new decision for this table, not a reused one.
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    alert: Mapped[Alert | None] = relationship(Alert)
    case: Mapped[Case | None] = relationship(Case)
