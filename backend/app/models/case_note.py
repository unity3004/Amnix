"""CaseNote: an immutable analyst journal entry attached to a Case
(Step 12R, architecture approved in Step 12Q).

A single CaseNote entity (no separate CaseComment entity — the two would
be the same shape; consolidating into one was an explicit Step 12Q
decision) rather than a mutable TEXT column on Case itself: a single
column would silently allow one analyst to overwrite another's notes
(data loss) and carries no per-entry authorship/timestamp/ordering.

v1 is deliberately fully IMMUTABLE — no edit endpoint, no delete
endpoint, matching AMNIX's existing "nothing is hard-deleted anywhere in
this codebase today" discipline (SecurityEvent/CopilotAudit/AdminAudit
are all append-only). `created_at` alone is the note's own authorship
record; no `updated_at` exists because there is no update path.

No CaseAudit row is created for note authorship (an explicit Step 12Q/
12R decision): the note row itself is already a timestamped, authored,
immutable record — a second audit entry would just duplicate the same
fact, exactly like CopilotAudit doesn't get a redundant AdminAudit entry
for each Copilot invocation.
"""

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Text, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class CaseNote(Base):
    """One immutable analyst journal entry attached to a Case."""

    __tablename__ = "case_notes"
    __table_args__ = (
        Index("ix_case_notes_case_id", "case_id"),
        CheckConstraint("length(btrim(body)) > 0", name="ck_case_notes_body_not_blank"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )

    # Pure compositional child of its Case (unlike CaseAudit's
    # accountability-preserving RESTRICT) -- a note is genuinely
    # meaningless once its Case is gone, mirroring alert_security_events'
    # own CASCADE reasoning for the same kind of relationship.
    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False
    )

    # RESTRICT: historical authorship must survive a later deactivation,
    # exactly like Case.owner_id/Case.created_by.
    author_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )

    body: Mapped[str] = mapped_column(Text, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
