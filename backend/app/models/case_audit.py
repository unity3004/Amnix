"""CaseAudit: a durable, append-only accountability record for every
meaningful Case mutation (Step 12R, architecture approved in Step 12Q).

Direct structural copy of app.models.admin_audit.AdminAudit — read that
module's own docstring for the full rationale behind each convention
reused here (actor FK RESTRICT-not-CASCADE, fixed-tuple action CHECK
constraint rather than a free-text column, append-only with no
`updated_at`, structured fields instead of an arbitrary JSON diff blob).

`case_id` uses RESTRICT, not CASCADE (unlike CaseAlert.case_id/
CaseNote.case_id, which ARE pure compositional children of their Case):
an audit row is an accountability record that must outlive its subject
exactly like AdminAudit's own rows must outlive the User rows they
describe — even though no Case-deletion endpoint exists today (mirroring
AdminAudit's own "RESTRICT is inert right now but a deliberate guard
against a future feature" reasoning).

One audit row always represents exactly ONE meaningful, well-defined
change — `previous_value`/`new_value` hold a plain-text representation
of that one field's before/after state, never a polymorphic multi-field
diff. A generic CASE_UPDATED action was explicitly rejected during
Step 12Q's architecture review for exactly this reason.
"""

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, Text, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

# The complete, fixed action vocabulary (Step 12Q, approved). Widening
# this is a deliberate future decision, exactly like AdminAudit's own
# ADMIN_AUDIT_ACTIONS — not something this schema is built to accept
# arbitrary new values for today.
CASE_AUDIT_ACTIONS = (
    "CASE_CREATED",
    "CASE_TITLE_CHANGED",
    "CASE_DESCRIPTION_CHANGED",
    "CASE_STATUS_CHANGED",
    "CASE_PRIORITY_CHANGED",
    "CASE_OWNER_CHANGED",
    "CASE_ALERT_LINKED",
    "CASE_ALERT_UNLINKED",
    "CASE_CLOSED",
    "CASE_REOPENED",
)

_LINK_ACTIONS = ("CASE_ALERT_LINKED", "CASE_ALERT_UNLINKED")


class CaseAudit(Base):
    """One durable, append-only row per meaningful successful Case
    mutation. See this module's own docstring for the full design
    rationale.
    """

    __tablename__ = "case_audits"
    __table_args__ = (
        Index("ix_case_audits_case_id", "case_id"),
        Index("ix_case_audits_actor_user_id", "actor_user_id"),
        Index("ix_case_audits_created_at", "created_at"),
        CheckConstraint(
            "action IN (" + ", ".join(f"'{a}'" for a in CASE_AUDIT_ACTIONS) + ")",
            name="ck_case_audits_action_valid",
        ),
        # Defense in depth, mirroring this project's established "don't
        # only trust application-layer discipline" philosophy (see e.g.
        # CopilotAudit.question_fingerprint's own CHECK constraint):
        # related_alert_id is required exactly for the two linking
        # actions and forbidden for every other action, enforced by the
        # database itself, not merely by CaseService's own construction
        # discipline.
        CheckConstraint(
            "(action IN (" + ", ".join(f"'{a}'" for a in _LINK_ACTIONS) + ") AND related_alert_id IS NOT NULL) "
            "OR (action NOT IN (" + ", ".join(f"'{a}'" for a in _LINK_ACTIONS) + ") AND related_alert_id IS NULL)",
            name="ck_case_audits_related_alert_id_matches_action",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )

    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id", ondelete="RESTRICT"), nullable=False
    )
    actor_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )

    # Server-controlled only — every CaseService method that constructs a
    # CaseAudit hardcodes exactly one literal action value; never accepted
    # from a client (there is no schema path that could supply one).
    action: Mapped[str] = mapped_column(String(30), nullable=False)

    related_alert_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="RESTRICT"), nullable=True
    )

    previous_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    new_value: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
