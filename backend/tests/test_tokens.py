"""Unit tests for app.core.tokens (Step 11D): JWT access-token
issuance/validation and opaque refresh-token generation/hashing. Pure
functions, no database required.

Relies on JWT_SECRET_KEY already being configured via the local .env
(see backend/.env) -- the same mechanism every other test in this suite
already relies on for database credentials.
"""

import uuid
from datetime import datetime, timedelta, timezone

import jwt as pyjwt
import pytest

from app.core.config import get_settings
from app.core.tokens import (
    InvalidAccessTokenError,
    create_access_token,
    decode_access_token,
    generate_refresh_token,
    hash_refresh_token,
)

# =============================================================================
# Access token issuance
# =============================================================================


def test_create_access_token_produces_a_decodable_jwt():
    user_id = uuid.uuid4()

    token = create_access_token(user_id=user_id, role="analyst")
    claims = decode_access_token(token)

    assert claims.user_id == user_id
    assert claims.role == "analyst"


def test_every_access_token_has_a_unique_jti():
    user_id = uuid.uuid4()

    first = decode_access_token(create_access_token(user_id=user_id, role="analyst"))
    second = decode_access_token(create_access_token(user_id=user_id, role="analyst"))

    assert first.jti != second.jti


def test_access_token_never_contains_password_shaped_content():
    token = create_access_token(user_id=uuid.uuid4(), role="analyst")

    for forbidden in ("password", "hash", "refresh"):
        assert forbidden not in token.lower()


def test_access_token_claims_match_required_shape():
    settings = get_settings()
    user_id = uuid.uuid4()

    token = create_access_token(user_id=user_id, role="admin")
    raw_claims = pyjwt.decode(token, settings.jwt_secret_key, algorithms=["HS256"], issuer="amnix", audience="amnix-api")

    assert set(raw_claims.keys()) == {"sub", "role", "iat", "exp", "jti", "iss", "aud"}
    assert raw_claims["sub"] == str(user_id)
    assert raw_claims["role"] == "admin"
    assert raw_claims["iss"] == "amnix"
    assert raw_claims["aud"] == "amnix-api"
    uuid.UUID(raw_claims["jti"])  # must be a real UUID string


# =============================================================================
# Access token validation
# =============================================================================


def test_decode_rejects_expired_token():
    settings = get_settings()
    now = datetime.now(timezone.utc)
    expired_payload = {
        "sub": str(uuid.uuid4()),
        "role": "analyst",
        "iat": now - timedelta(minutes=30),
        "exp": now - timedelta(minutes=15),
        "jti": str(uuid.uuid4()),
        "iss": "amnix",
        "aud": "amnix-api",
    }
    expired_token = pyjwt.encode(expired_payload, settings.jwt_secret_key, algorithm="HS256")

    with pytest.raises(InvalidAccessTokenError):
        decode_access_token(expired_token)


def test_decode_rejects_tampered_signature():
    token = create_access_token(user_id=uuid.uuid4(), role="analyst")
    tampered = token[:-4] + ("AAAA" if token[-4:] != "AAAA" else "BBBB")

    with pytest.raises(InvalidAccessTokenError):
        decode_access_token(tampered)


def test_decode_rejects_malformed_token():
    with pytest.raises(InvalidAccessTokenError):
        decode_access_token("not.a.jwt")


def test_decode_rejects_alg_none():
    """A token signed (unsigned, really) with alg=none must never be
    accepted regardless of what its header claims -- decode_access_token
    always passes algorithms=["HS256"] explicitly, so the token's own
    `alg` header is never consulted to select verification behavior.
    """
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(uuid.uuid4()),
        "role": "analyst",
        "iat": now,
        "exp": now + timedelta(minutes=15),
        "jti": str(uuid.uuid4()),
        "iss": "amnix",
        "aud": "amnix-api",
    }
    none_token = pyjwt.encode(payload, "", algorithm="none")

    with pytest.raises(InvalidAccessTokenError):
        decode_access_token(none_token)


def test_decode_rejects_alternate_algorithm():
    """A token signed with a different (even if otherwise valid)
    algorithm than HS256 must be rejected.
    """
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(uuid.uuid4()),
        "role": "analyst",
        "iat": now,
        "exp": now + timedelta(minutes=15),
        "jti": str(uuid.uuid4()),
        "iss": "amnix",
        "aud": "amnix-api",
    }
    hs384_token = pyjwt.encode(payload, get_settings().jwt_secret_key, algorithm="HS384")

    with pytest.raises(InvalidAccessTokenError):
        decode_access_token(hs384_token)


def test_decode_rejects_wrong_issuer():
    settings = get_settings()
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(uuid.uuid4()),
        "role": "analyst",
        "iat": now,
        "exp": now + timedelta(minutes=15),
        "jti": str(uuid.uuid4()),
        "iss": "not-amnix",
        "aud": "amnix-api",
    }
    token = pyjwt.encode(payload, settings.jwt_secret_key, algorithm="HS256")

    with pytest.raises(InvalidAccessTokenError):
        decode_access_token(token)


def test_decode_rejects_wrong_audience():
    settings = get_settings()
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(uuid.uuid4()),
        "role": "analyst",
        "iat": now,
        "exp": now + timedelta(minutes=15),
        "jti": str(uuid.uuid4()),
        "iss": "amnix",
        "aud": "not-amnix-api",
    }
    token = pyjwt.encode(payload, settings.jwt_secret_key, algorithm="HS256")

    with pytest.raises(InvalidAccessTokenError):
        decode_access_token(token)


@pytest.mark.parametrize("missing_claim", ["sub", "role", "iat", "exp", "jti", "iss", "aud"])
def test_decode_rejects_missing_required_claim(missing_claim):
    settings = get_settings()
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(uuid.uuid4()),
        "role": "analyst",
        "iat": now,
        "exp": now + timedelta(minutes=15),
        "jti": str(uuid.uuid4()),
        "iss": "amnix",
        "aud": "amnix-api",
    }
    del payload[missing_claim]
    token = pyjwt.encode(payload, settings.jwt_secret_key, algorithm="HS256")

    with pytest.raises(InvalidAccessTokenError):
        decode_access_token(token)


def test_decode_rejects_invalid_subject():
    settings = get_settings()
    now = datetime.now(timezone.utc)
    payload = {
        "sub": "not-a-uuid",
        "role": "analyst",
        "iat": now,
        "exp": now + timedelta(minutes=15),
        "jti": str(uuid.uuid4()),
        "iss": "amnix",
        "aud": "amnix-api",
    }
    token = pyjwt.encode(payload, settings.jwt_secret_key, algorithm="HS256")

    with pytest.raises(InvalidAccessTokenError):
        decode_access_token(token)


def test_decode_rejects_invalid_role():
    settings = get_settings()
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(uuid.uuid4()),
        "role": "superadmin",
        "iat": now,
        "exp": now + timedelta(minutes=15),
        "jti": str(uuid.uuid4()),
        "iss": "amnix",
        "aud": "amnix-api",
    }
    token = pyjwt.encode(payload, settings.jwt_secret_key, algorithm="HS256")

    with pytest.raises(InvalidAccessTokenError):
        decode_access_token(token)


def test_decode_rejects_invalid_jti():
    settings = get_settings()
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(uuid.uuid4()),
        "role": "analyst",
        "iat": now,
        "exp": now + timedelta(minutes=15),
        "jti": "not-a-uuid",
        "iss": "amnix",
        "aud": "amnix-api",
    }
    token = pyjwt.encode(payload, settings.jwt_secret_key, algorithm="HS256")

    with pytest.raises(InvalidAccessTokenError):
        decode_access_token(token)


def test_decode_rejects_client_supplied_arbitrary_algorithm_confusion():
    """A token whose header claims HS256 but was actually signed with a
    key derived differently (simulating a naive "trust the header"
    implementation) must still only verify against the real configured
    secret -- proven simply by confirming a token signed with the wrong
    secret entirely is rejected.
    """
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(uuid.uuid4()),
        "role": "analyst",
        "iat": now,
        "exp": now + timedelta(minutes=15),
        "jti": str(uuid.uuid4()),
        "iss": "amnix",
        "aud": "amnix-api",
    }
    wrong_secret_token = pyjwt.encode(payload, "a-completely-different-secret-key-value", algorithm="HS256")

    with pytest.raises(InvalidAccessTokenError):
        decode_access_token(wrong_secret_token)


def test_invalid_access_token_error_message_is_generic():
    try:
        decode_access_token("garbage")
    except InvalidAccessTokenError as exc:
        assert str(exc) == "Invalid or expired access token."


# =============================================================================
# Refresh token generation / hashing
# =============================================================================


def test_generate_refresh_token_produces_high_entropy_opaque_strings():
    first = generate_refresh_token()
    second = generate_refresh_token()

    assert first != second
    assert len(first) >= 32
    # Never a JWT (no dot-separated header.payload.signature shape) and
    # never a plain UUID string.
    assert first.count(".") == 0
    with pytest.raises(ValueError):
        uuid.UUID(first)


def test_hash_refresh_token_is_deterministic_and_64_char_lowercase_hex():
    raw = generate_refresh_token()

    first_hash = hash_refresh_token(raw)
    second_hash = hash_refresh_token(raw)

    assert first_hash == second_hash
    assert len(first_hash) == 64
    assert first_hash == first_hash.lower()
    int(first_hash, 16)  # raises ValueError if not valid hex


def test_hash_refresh_token_differs_for_different_tokens():
    assert hash_refresh_token(generate_refresh_token()) != hash_refresh_token(generate_refresh_token())


def test_hash_refresh_token_never_returns_the_raw_token():
    raw = generate_refresh_token()

    assert hash_refresh_token(raw) != raw
