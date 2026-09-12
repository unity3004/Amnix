"""AdminAudit: a durable, append-only accountability record for a
successful administrative operation (Step 11M).

NOT the same subsystem as app.core.security_events (Step 11J) or
CopilotAudit (Step 10F) — see this module's docstring below for the
full distinction. Do not conflate the three; each has its own contract
and none of them is repurposed to satisfy another's need.

WHY A NEW MODEL, NOT A REUSE OF EXISTING ONES (Step 11M discovery):
    No generic audit model exists anywhere in AMNIX. CopilotAudit (see
    app.models.copilot_audit) is a Copilot-invocation audit trail with
    its own fixed contract (alert_id, request_type, provider_name,
    question_fingerprint, ...) — it has no actor/target concept at all
    and is explicitly NOT to be modified or repurposed for this feature
    (per the Step 11M brief). app.core.security_events.SecurityEvent is
    an in-memory dataclass logged to stdout via the "amnix.security"
    logger — it is never persisted anywhere and was never meant to be a
    durable, queryable historical record; it answers "did a security-
    relevant event occur" for operational observability, not "give me
    every administrative action ever taken against this account" for
    accountability/investigation. AdminAudit is the first and only model
    that answers the second question.

DISTINCT FROM SecurityEventType.ADMIN_USER_STATUS_CHANGED:
    A successful status change still emits that SecurityEvent (Step 11J,
    unmodified — see app.api.admin) AND creates exactly one AdminAudit
    row. The two serve different purposes and are allowed to coexist
    reporting the same real-world event: the SecurityEvent is an
    operational log line (stdout, ephemeral, not queryable after the
    fact except via whatever external log collection a deployment adds);
    AdminAudit is a durable, structured, directly queryable PostgreSQL
    row this application itself can retrieve via GET /admin/audits.

SCOPE (Step 11M): exactly one audited operation exists today —
PATCH /admin/users/{user_id}/status, recorded with `action =
"USER_STATUS_CHANGED"`. This is NOT a generic audit framework; adding a
second audited operation is a deliberate future decision (would mean
widening the `action` CHECK constraint and adding whatever new
before/after fields that operation needs), not something this schema
is built to accept arbitrary new fields for today.

ACTOR/TARGET FOREIGN KEYS — ondelete='RESTRICT', not CASCADE:
    Every other FK in AMNIX that references a parent whose deletion
    should also delete its children uses CASCADE (refresh_tokens.
    user_id, copilot_audits.alert_id, alert_security_events.*) —
    because those child rows genuinely have no independent meaning once
    their parent is gone. An AdminAudit row is the opposite: it MUST
    outlive both the actor and target User rows it references, because
    its entire purpose is to answer "who did what to whom" durably, even
    long after either account might later be removed. AMNIX has no
    user-deletion endpoint today (verified during discovery — deliberately
    not added by this step either), so RESTRICT is inert right now, but
    it is a deliberate guard against a FUTURE user-deletion feature
    silently cascading away accountability history: attempting to delete
    a User who is referenced by any AdminAudit row (as either actor or
    target) will fail loudly with a foreign-key violation, forcing
    whoever eventually builds user deletion to make an explicit decision
    (e.g. archive first, or refuse to delete audited accounts) rather
    than accidentally erasing history. Deactivating a user (the ONLY
    lifecycle operation that exists today) never touches this FK at all.

IDEMPOTENT (no-op) STATUS CHANGES ARE STILL AUDITED:
    UserService.set_active_status() is idempotent by design — setting an
    already-inactive account inactive again is a normal, successful
    200, not a special "nothing happened" response (see
    app.services.user_service's own docstring/tests). This model
    therefore records EVERY successful invocation, including one where
    `previous_is_active == new_is_active` — there is no CHECK constraint
    forbidding that shape. Reasoning: the existing API/service layer
    already treats a no-op request as an ordinary success, so recording
    it identically is the choice that stays consistent with behavior
    that already exists elsewhere, rather than inventing a new "was this
    actually a change" distinction nothing else in AMNIX draws. It also
    means the audit trail reflects every time an admin actually invoked
    this operation against an account, not just every time the value
    happened to flip — a more complete accountability record, not a
    weaker one.

SELF-TARGET / FAILED OPERATIONS NEVER REACH THIS TABLE AT ALL: a 409
(self-target), 404 (nonexistent target), 403 (non-admin caller), or 401
(authentication failure) never causes a row to be constructed in the
first place — see app.services.admin_audit_service.AdminAuditService,
which only ever builds an AdminAudit after UserService's own validation
has already passed.

TRANSACTIONAL GUARANTEE: see app.services.admin_audit_service's own
docstring for the full write-up. Summary: the User mutation and this
row's INSERT are committed in the SAME database transaction — either
both persist or neither does. There is no code path that can produce an
AdminAudit row for a User mutation that did not actually commit, and
none that can commit a User mutation for this operation without also
committing its AdminAudit row.

DELIBERATELY EXCLUDED FROM THIS MODEL, same "don't invent unneeded
columns" discipline CopilotAudit's own docstring already establishes:
no raw request body, no Authorization header, no JWT, no password, no
password hash, no refresh token/hash, no arbitrary JSON payload column.
Every field here is a small, fixed, already-safe value.
"""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, String, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

# The complete, fixed action vocabulary this table accepts today — see
# this module's own docstring on why widening it is a deliberate future
# decision, not something the schema is built to accept arbitrary new
# values for. Mirrors app.schemas.admin_audit.AdminAuditAction exactly.
ADMIN_AUDIT_ACTIONS = ("USER_STATUS_CHANGED",)


class AdminAudit(Base):
    """One durable, append-only row per successful administrative
    operation. See this module's docstring for the full design
    rationale (actor/target FK behavior, idempotent-operation semantics,
    the transactional guarantee, and the distinction from both
    CopilotAudit and app.core.security_events).

    Append-only, like CopilotAudit/SecurityEvent: an audit row records a
    fact about a past action, so there is no `updated_at` and this
    model/its repository expose no update path at all — see
    app.repositories.admin_audit.AdminAuditRepository, which only ever
    supports create-without-commit and read operations.
    """

    __tablename__ = "admin_audits"
    __table_args__ = (
        Index("ix_admin_audits_actor_user_id", "actor_user_id"),
        Index("ix_admin_audits_target_user_id", "target_user_id"),
        Index("ix_admin_audits_created_at", "created_at"),
        # Built via a plain joined string, not `{ADMIN_AUDIT_ACTIONS!r}`
        # (Python's tuple repr) -- a single-element tuple reprs as
        # "('USER_STATUS_CHANGED',)", and that trailing comma before the
        # closing paren is invalid SQL for an `IN (...)` list (verified
        # live: PostgreSQL rejected it outright when this table was
        # first created). Joining the quoted values directly produces
        # correct SQL regardless of how many action values exist.
        CheckConstraint(
            "action IN (" + ", ".join(f"'{action}'" for action in ADMIN_AUDIT_ACTIONS) + ")",
            name="ck_admin_audits_action_valid",
        ),
        # Defense in depth, mirroring this project's established "don't
        # only trust application-layer discipline" philosophy (see e.g.
        # CopilotAudit.question_fingerprint's own CHECK constraint): the
        # service layer already refuses to construct a self-targeted
        # audit row at all (UserService raises CannotModifyOwnAccountError
        # before AdminAuditService ever builds one), but the database
        # itself also makes it structurally impossible to insert one.
        CheckConstraint("actor_user_id != target_user_id", name="ck_admin_audits_actor_not_target"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )

    actor_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    target_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )

    # Server-controlled only — see app.services.admin_audit_service;
    # never accepted from a client. String(30) is generous headroom
    # above the one current value ("USER_STATUS_CHANGED", 20 chars)
    # without being tightly fitted to today's exact vocabulary.
    action: Mapped[str] = mapped_column(String(30), nullable=False)

    previous_is_active: Mapped[bool] = mapped_column(Boolean, nullable=False)
    new_is_active: Mapped[bool] = mapped_column(Boolean, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
