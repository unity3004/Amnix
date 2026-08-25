"""SecurityEvent: normalized representation of ingested security telemetry."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, DateTime, Index, Integer, String, Text, func, text
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class SecurityEvent(Base):
    """One normalized unit of security telemetry.

    Every ingestion source (Windows Event Log, Sysmon, Linux auth log,
    network sensors, future SIEM feeds, ...) is normalized into this same
    shape at ingestion time, so detection/correlation/investigation code
    downstream never needs to understand source-specific formats directly.
    The original payload is always preserved in `raw_data` for that purpose.

    This table is treated as append-only: security telemetry is not edited
    after ingestion, so there is no `updated_at` column and no update path.
    """

    __tablename__ = "security_events"
    __table_args__ = (
        Index("ix_security_events_event_timestamp", "event_timestamp"),
        Index("ix_security_events_hostname", "hostname"),
        Index("ix_security_events_username", "username"),
        Index("ix_security_events_source_ip", "source_ip"),
        Index("ix_security_events_destination_ip", "destination_ip"),
        Index("ix_security_events_source", "source"),
        Index("ix_security_events_event_type", "event_type"),
        Index(
            "uq_security_events_source_dedup",
            "source",
            "source_event_id",
            unique=True,
            postgresql_where=text("source_event_id IS NOT NULL"),
        ),
        CheckConstraint("length(btrim(event_type)) > 0", name="ck_security_events_event_type_not_blank"),
        CheckConstraint("length(btrim(source)) > 0", name="ck_security_events_source_not_blank"),
        CheckConstraint(
            "source_port IS NULL OR (source_port >= 0 AND source_port <= 65535)",
            name="ck_security_events_source_port_range",
        ),
        CheckConstraint(
            "destination_port IS NULL OR (destination_port >= 0 AND destination_port <= 65535)",
            name="ck_security_events_destination_port_range",
        ),
        CheckConstraint(
            "severity IS NULL OR severity IN ('informational', 'low', 'medium', 'high', 'critical')",
            name="ck_security_events_severity_valid",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )

    # When the event occurred at the source, per the telemetry itself —
    # the field investigators reason about. Distinct from `created_at`
    # (when AMNIX ingested it), which can lag behind due to forwarding
    # delay, batch uploads, or clock skew.
    event_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    source_event_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    username: Mapped[str | None] = mapped_column(String(255), nullable=True)

    source_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)

    process_name: Mapped[str | None] = mapped_column(String(500), nullable=True)
    process_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    parent_process_name: Mapped[str | None] = mapped_column(String(500), nullable=True)
    command_line: Mapped[str | None] = mapped_column(Text, nullable=True)

    file_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    file_path: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Source-reported severity/level (e.g. Windows Event level, syslog
    # severity), NOT an AMNIX-assessed risk score — that belongs to a
    # future Alert/Detection model.
    severity: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # Untouched original payload, preserved for investigator drill-down.
    raw_data: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)

    # Curated-but-flexible extension bag for source-specific fields that
    # don't warrant becoming top-level columns yet. Distinct from
    # raw_data: this is meant to hold normalized-ish extras, not the
    # original blob.
    event_metadata: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
