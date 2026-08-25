"""Alert: a trackable SOC investigation item generated from one or more
DetectionResults, referencing the SecurityEvents that justify it.

Domain distinction (do not collapse these):
  SecurityEvent    — telemetry: what happened.
  DetectionResult  — a detection decision: why the behavior is suspicious.
                      Ephemeral, computed on demand by the DetectionEngine
                      (see app.schemas.detection) — never persisted itself.
  Alert            — a trackable investigation item: what the analyst
                      needs to work. Persisted, carries a lifecycle.

Unlike SecurityEvent, an Alert is NOT append-only: its `status` changes
over its lifecycle, so (unlike SecurityEvent) it has an `updated_at`
column that changes after creation.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    String,
    Table,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.security_event import SecurityEvent

# Pure many-to-many join table: an Alert can be justified by multiple
# SecurityEvents, and a single SecurityEvent can be evidence for
# multiple Alerts (e.g. it contributes to two different rules firing).
#
# Deletion behavior is intentionally asymmetric:
#   - alert_id ondelete=CASCADE: a join row is meaningless once its
#     Alert is gone, so it's safe (and desirable) to clean it up
#     automatically.
#   - security_event_id ondelete=RESTRICT: deleting a SecurityEvent
#     that is still cited as evidence for an Alert must fail loudly
#     instead of silently erasing that evidence. There is no delete
#     endpoint for either model yet, but the constraint is the actual
#     integrity guarantee, not any application-layer check.
alert_security_events = Table(
    "alert_security_events",
    Base.metadata,
    Column("alert_id", UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True),
    Column(
        "security_event_id",
        UUID(as_uuid=True),
        ForeignKey("security_events.id", ondelete="RESTRICT"),
        primary_key=True,
    ),
    Index("ix_alert_security_events_security_event_id", "security_event_id"),
)


class Alert(Base):
    """A trackable SOC investigation item generated from detection output."""

    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_status", "status"),
        Index("ix_alerts_rule_id", "rule_id"),
        Index("ix_alerts_first_seen", "first_seen"),
        CheckConstraint("length(btrim(rule_id)) > 0", name="ck_alerts_rule_id_not_blank"),
        CheckConstraint("length(btrim(title)) > 0", name="ck_alerts_title_not_blank"),
        CheckConstraint(
            "severity IN ('low', 'medium', 'high', 'critical')",
            name="ck_alerts_severity_valid",
        ),
        CheckConstraint(
            "confidence IN ('low', 'medium', 'high')",
            name="ck_alerts_confidence_valid",
        ),
        CheckConstraint(
            "status IN ('new', 'acknowledged', 'investigating', 'resolved', 'escalated')",
            name="ck_alerts_status_valid",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )

    # Identifies which detection rule produced this alert. Not a foreign
    # key: rules are Python objects in the DetectionRuleRegistry, not a
    # database table.
    rule_id: Mapped[str] = mapped_column(String(100), nullable=False)

    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    # AMNIX's own assessment of impact/certainty — see
    # app.schemas.detection for why these are distinct from
    # SecurityEvent.severity (source-reported) and from each other.
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    confidence: Mapped[str] = mapped_column(String(20), nullable=False)

    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default=text("'new'"))

    # When the underlying behavior was first/most-recently observed, as
    # opposed to `created_at` (when AMNIX recorded this Alert row). Every
    # alert starts with first_seen == last_seen; a future
    # de-duplication/merge pass could advance last_seen on repeat
    # triggers of the same condition, but no such merge logic exists
    # yet — see the final report.
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    # Structured evidence (e.g. a brute-force alert's failure_count,
    # username, source_ip, window_seconds — see the detection rules).
    # Not a free-text explanation: this must remain queryable/inspectable.
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)

    # Extension bag for future analyst/enrichment annotations, distinct
    # from `evidence` (which is why the alert exists, not commentary on
    # it). Named alert_metadata to avoid colliding with
    # Base.metadata, same reasoning as SecurityEvent.event_metadata.
    alert_metadata: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)

    security_events: Mapped[list[SecurityEvent]] = relationship(
        SecurityEvent,
        secondary=alert_security_events,
        backref="alerts",
    )

    @property
    def source_event_ids(self) -> list[uuid.UUID]:
        """IDs of the SecurityEvents that justify this alert."""
        return [event.id for event in self.security_events]
