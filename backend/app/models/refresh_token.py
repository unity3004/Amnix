"""RefreshToken: an opaque, rotate-on-use session token (Step 11D).

See app.core.tokens for generation (generate_refresh_token()) and
hashing (hash_refresh_token()) — this model never stores or sees the
raw token, only its SHA-256 hex digest, mirroring exactly how
CopilotAudit.question_fingerprint stores a hash rather than raw content
(see app.models.copilot_audit) and how User.password_hash never stores
a plaintext password (see app.models.user). The
ck_refresh_tokens_token_hash_sha256_hex CHECK constraint is the same
"the database itself makes storing raw content impossible" defense in
depth those two columns already establish.

Rotation model: every fresh login starts a new `family_id`
(app.services.token_service.TokenService.issue_new_login_tokens).
Refreshing rotates a token: the presented token is marked
`revoked_at` + `replaced_by_id` (pointing at its successor) in the same
transaction that inserts the successor, and the successor keeps the
same `family_id`. Presenting a token that already has `revoked_at` set
is therefore reuse of an already-rotated (or explicitly revoked) token
— see TokenService.refresh()'s own docstring for why that revokes the
entire family rather than just rejecting the one request.

user_id uses ondelete="CASCADE": a refresh token has no independent
meaning once its User is gone, exactly the same reasoning
alert_security_events.alert_id and copilot_audits.alert_id already use
for their own parent relationships (see app.models.alert /
app.models.copilot_audit). replaced_by_id uses ondelete="SET NULL": if
a successor row were ever deleted (no delete endpoint exists for this
table, but as a safety net), the predecessor's pointer should become
NULL rather than cascade-deleting backward through the rotation chain
or blocking the delete.

No `created_at` column: `issued_at` already captures the one moment
that matters (a refresh token row is always created at exactly the
moment it is issued — unlike Alert, where first_seen/created_at can
genuinely differ, these would always be identical here, so adding both
would be pure duplication). No `updated_at` either: `revoked_at` itself
already is the timestamp of the one state transition this row ever
undergoes.
"""

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class RefreshToken(Base):
    """One node in a refresh-token rotation chain. See this module's
    docstring for the full rotation/reuse-detection model.
    """

    __tablename__ = "refresh_tokens"
    __table_args__ = (
        Index("ix_refresh_tokens_user_id", "user_id"),
        Index("ix_refresh_tokens_token_hash", "token_hash", unique=True),
        Index("ix_refresh_tokens_family_id", "family_id"),
        CheckConstraint(
            "token_hash ~ '^[0-9a-f]{64}$'", name="ck_refresh_tokens_token_hash_sha256_hex"
        ),
        CheckConstraint(
            "replaced_by_id IS NULL OR revoked_at IS NOT NULL",
            name="ck_refresh_tokens_replaced_implies_revoked",
        ),
        CheckConstraint(
            "replaced_by_id IS NULL OR replaced_by_id != id",
            name="ck_refresh_tokens_replaced_by_not_self",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )

    # SHA-256 hex digest of the raw opaque refresh token — see this
    # module's docstring and app.core.tokens.hash_refresh_token(). Never
    # the raw token itself.
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    # Shared by every token in one rotation chain — see this module's
    # docstring for exactly when a new one is minted vs. carried forward.
    family_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)

    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    replaced_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("refresh_tokens.id", ondelete="SET NULL"), nullable=True
    )
