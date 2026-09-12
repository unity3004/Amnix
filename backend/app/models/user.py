"""User: an AMNIX analyst/admin identity.

Step 11B — database/crypto foundation only. No authentication endpoints,
no JWT, no login/session/token logic exists yet — see app.core.security
for the password-hashing/email-normalization utilities this step adds.
Wiring this into actual authentication (login, tokens, middleware,
authorization enforcement) is later work; see Step 11A's approved
architecture for the full roadmap.

role is a fixed, small vocabulary ('analyst' | 'admin') enforced by a
CHECK constraint, exactly like Alert.status/.severity/.confidence — not
a separate roles/permissions table, matching how every other
fixed-vocabulary field in AMNIX is modeled. There is no Role ORM model
and no user_roles join table; revisit only if a real requirement for
dynamic per-user permissions emerges (see Step 11A's explicit decision
to defer that).

email uniqueness is enforced here in its stored (already-normalized)
form. Normalization itself (strip + lowercase) is NOT performed by this
model or by UserRepository — it is the caller's responsibility, via
app.core.security.normalize_email(), before ever constructing a User
instance. This mirrors how Alert/SecurityEvent's repositories also
perform no validation or transformation on what they're given; that
belongs to the service/schema layer, which for User does not exist yet
in this step (there is no registration endpoint to own it).

password_hash stores ONLY a complete Argon2id PHC-format hash string
(see app.core.security.hash_password) — never a plaintext password,
never a separate salt/parameter set. The CHECK constraint that it must
start with '$argon2id$' is deliberate defense in depth: it makes it
impossible for this column to ever hold a plaintext value or a hash from
a weaker scheme, exactly like CopilotAudit.question_fingerprint's own
CHECK constraint mechanically enforces its value can only be a real
SHA-256 hex digest (see app.models.copilot_audit) — the same "don't only
trust application-layer discipline" philosophy applied to a different
column.

Like Alert (and unlike the append-only SecurityEvent/CopilotAudit), a
User is not append-only: is_active and password_hash can both change
after creation (deactivation, password change), so this has an
`updated_at` that changes over time, following Alert's exact pattern.
"""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, Index, String, Text, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class User(Base):
    """An AMNIX analyst or admin identity. See this module's docstring
    for the full rationale behind each field and constraint.
    """

    __tablename__ = "users"
    __table_args__ = (
        Index("ix_users_email", "email", unique=True),
        CheckConstraint("length(btrim(email)) > 0", name="ck_users_email_not_blank"),
        CheckConstraint(
            "length(btrim(password_hash)) > 0", name="ck_users_password_hash_not_blank"
        ),
        # Defense in depth: only a real Argon2id PHC-format hash can ever
        # be stored here — see this module's docstring.
        CheckConstraint(
            r"password_hash ~ '^\$argon2id\$'", name="ck_users_password_hash_is_argon2id"
        ),
        CheckConstraint("role IN ('analyst', 'admin')", name="ck_users_role_valid"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )

    # 320 = RFC 5321's theoretical maximum email length (64-character
    # local part + '@' + 255-character domain). Always stored already
    # normalized (stripped + lowercased) — see this module's docstring
    # for exactly where that normalization happens.
    email: Mapped[str] = mapped_column(String(320), nullable=False)

    password_hash: Mapped[str] = mapped_column(Text, nullable=False)

    role: Mapped[str] = mapped_column(String(20), nullable=False)

    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
