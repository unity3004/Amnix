"""Pydantic schemas for SecurityEvent API input/output."""

import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator

# Ingestion boundary limits. Security telemetry sources are not fully
# trusted: a misbehaving or compromised forwarder could send oversized or
# malformed payloads. These caps bound the damage at the API edge, before
# anything reaches the database.
MAX_RAW_DATA_BYTES = 256 * 1024
MAX_METADATA_BYTES = 64 * 1024
MAX_COMMAND_LINE_LENGTH = 32_768
MAX_FUTURE_SKEW = timedelta(hours=24)

_HASH_PATTERN = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$|^[A-Fa-f0-9]{128}$")


class Severity(str, Enum):
    """Source-reported severity/level, not an AMNIX-assessed risk score."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def _json_size(value: dict[str, Any]) -> int:
    return len(json.dumps(value).encode("utf-8"))


class SecurityEventBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_timestamp: datetime
    event_type: str = Field(min_length=1, max_length=100)
    source: str = Field(min_length=1, max_length=100)
    source_event_id: str | None = Field(default=None, max_length=255)

    hostname: str | None = Field(default=None, max_length=255)
    username: str | None = Field(default=None, max_length=255)

    source_ip: IPvAnyAddress | None = None
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_ip: IPvAnyAddress | None = None
    destination_port: int | None = Field(default=None, ge=0, le=65535)

    process_name: str | None = Field(default=None, max_length=500)
    process_id: int | None = Field(default=None, ge=0)
    parent_process_name: str | None = Field(default=None, max_length=500)
    command_line: str | None = Field(default=None, max_length=MAX_COMMAND_LINE_LENGTH)

    file_hash: str | None = Field(default=None, max_length=128)
    file_path: str | None = Field(default=None, max_length=4096)

    severity: Severity | None = None

    raw_data: dict[str, Any]
    event_metadata: dict[str, Any] | None = None

    @field_validator("event_type", "source")
    @classmethod
    def _not_blank(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("must not be blank")
        return stripped

    @field_validator("event_timestamp")
    @classmethod
    def _timestamp_tz_aware_and_sane(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("event_timestamp must be timezone-aware")
        if v > datetime.now(timezone.utc) + MAX_FUTURE_SKEW:
            raise ValueError("event_timestamp is too far in the future")
        return v

    @field_validator("raw_data")
    @classmethod
    def _raw_data_bounded(cls, v: dict[str, Any]) -> dict[str, Any]:
        if _json_size(v) > MAX_RAW_DATA_BYTES:
            raise ValueError(f"raw_data exceeds maximum size of {MAX_RAW_DATA_BYTES} bytes")
        return v

    @field_validator("event_metadata")
    @classmethod
    def _metadata_bounded(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        if v is not None and _json_size(v) > MAX_METADATA_BYTES:
            raise ValueError(f"event_metadata exceeds maximum size of {MAX_METADATA_BYTES} bytes")
        return v

    @field_validator("file_hash")
    @classmethod
    def _file_hash_format(cls, v: str | None) -> str | None:
        if v is not None and not _HASH_PATTERN.match(v):
            raise ValueError("file_hash must be a valid MD5/SHA1/SHA256/SHA512 hex digest")
        return v


class SecurityEventCreate(SecurityEventBase):
    """Input schema for POST /events."""


class SecurityEventRead(SecurityEventBase):
    """Output schema for retrieved security events."""

    model_config = ConfigDict(from_attributes=True, extra="ignore")

    id: uuid.UUID
    created_at: datetime
