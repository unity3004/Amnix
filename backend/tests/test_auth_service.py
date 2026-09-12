"""Integration tests for AuthService (Step 11C registration/login,
extended in Step 11D with token issuance on login). Require PostgreSQL
(see conftest.py's db_session fixture).
"""

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.core.security import PasswordTooShortError, hash_password, normalize_email, verify_password
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.repositories.refresh_token import RefreshTokenRepository
from app.repositories.user import UserRepository
from app.services.auth_service import AuthService, EmailAlreadyRegisteredError, InvalidCredentialsError
from app.services.token_service import TokenService

pytestmark = pytest.mark.integration

VALID_PASSWORD = "correct horse battery staple"


def _service(db_session) -> AuthService:
    token_service = TokenService(RefreshTokenRepository(db_session), UserRepository(db_session))
    return AuthService(UserRepository(db_session), token_service)


def _unique_email(prefix: str = "analyst") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}@example.com"


# =============================================================================
# Registration
# =============================================================================


def test_successful_registration(db_session):
    email = _unique_email()
    service = _service(db_session)

    user = service.register(email, VALID_PASSWORD)

    assert user.id is not None
    assert user.email == email
    assert user.role == "analyst"
    assert user.is_active is True


def test_registration_normalizes_email(db_session):
    raw_email = f"  Analyst-{uuid.uuid4().hex[:8]}@Example.COM  "
    service = _service(db_session)

    user = service.register(raw_email, VALID_PASSWORD)

    assert user.email == normalize_email(raw_email)
    assert user.email == user.email.strip().lower()


def test_registration_default_role_is_analyst(db_session):
    user = _service(db_session).register(_unique_email(), VALID_PASSWORD)

    assert user.role == "analyst"


def test_registration_stores_only_argon2id_hash_never_plaintext(db_session):
    user = _service(db_session).register(_unique_email(), VALID_PASSWORD)

    assert user.password_hash != VALID_PASSWORD
    assert user.password_hash.startswith("$argon2id$")
    assert verify_password(VALID_PASSWORD, user.password_hash) is True


def test_registration_rejects_password_below_minimum_length(db_session):
    with pytest.raises(PasswordTooShortError):
        _service(db_session).register(_unique_email(), "short11ch")


def test_registration_accepts_password_at_exactly_minimum_length(db_session):
    user = _service(db_session).register(_unique_email(), "a" * 12)

    assert user.id is not None


def test_registration_does_not_issue_tokens(db_session):
    """Step 11D: register() still returns a bare User, not a
    LoginResult -- no token of any kind is issued at registration (see
    app.services.auth_service's own docstring for why discovery showed
    this isn't needed).
    """
    user = _service(db_session).register(_unique_email(), VALID_PASSWORD)

    assert isinstance(user, User)
    assert not hasattr(user, "access_token")


def test_registration_creates_no_refresh_token_row(db_session):
    email = _unique_email()
    _service(db_session).register(email, VALID_PASSWORD)

    rows = list(db_session.scalars(select(RefreshToken)))
    assert rows == []


def test_registration_duplicate_email_is_rejected(db_session):
    email = _unique_email()
    service = _service(db_session)
    service.register(email, VALID_PASSWORD)

    with pytest.raises(EmailAlreadyRegisteredError):
        service.register(email, VALID_PASSWORD)


def test_registration_duplicate_email_case_and_whitespace_insensitive(db_session):
    base = f"dup-{uuid.uuid4().hex[:8]}@example.com"
    service = _service(db_session)
    service.register(base, VALID_PASSWORD)

    with pytest.raises(EmailAlreadyRegisteredError):
        service.register(f"  {base.upper()}  ", VALID_PASSWORD)


def test_registration_concurrent_race_is_translated_to_the_same_conflict_error(db_session, monkeypatch):
    """Simulates a concurrent registration that already committed the
    same normalized email before this call's own get_by_email()
    pre-check ran -- forcing the database's unique index itself (not the
    pre-check) to be what actually rejects the insert, exactly like two
    real concurrent requests racing each other would. get_by_email() is
    patched to return None so the pre-check cannot short-circuit the
    scenario this test exists to prove: UserRepository.create()'s own
    IntegrityError handling (see its module docstring) recovers the
    session and AuthService still translates it to the same typed
    conflict.
    """
    email = _unique_email()
    db_session.add(User(email=email, password_hash=hash_password("another password entirely"), role="analyst"))
    db_session.commit()

    monkeypatch.setattr(UserRepository, "get_by_email", lambda self, email: None)
    service = _service(db_session)

    with pytest.raises(EmailAlreadyRegisteredError):
        service.register(email, VALID_PASSWORD)


def test_registration_error_message_is_generic(db_session):
    email = _unique_email()
    service = _service(db_session)
    service.register(email, VALID_PASSWORD)

    with pytest.raises(EmailAlreadyRegisteredError) as exc_info:
        service.register(email, VALID_PASSWORD)

    assert str(exc_info.value) == "Email is already registered."


# =============================================================================
# Login
# =============================================================================


def test_login_with_valid_credentials_succeeds(db_session):
    email = _unique_email()
    service = _service(db_session)
    service.register(email, VALID_PASSWORD)

    result = service.login(email, VALID_PASSWORD)

    assert result.user.email == email
    assert result.access_token
    assert result.refresh_token
    assert result.expires_in == 15 * 60


def test_login_with_wrong_password_fails(db_session):
    email = _unique_email()
    service = _service(db_session)
    service.register(email, VALID_PASSWORD)

    with pytest.raises(InvalidCredentialsError):
        service.login(email, "completely wrong password")


def test_login_with_nonexistent_email_fails(db_session):
    with pytest.raises(InvalidCredentialsError):
        _service(db_session).login("nobody-registered@example.com", VALID_PASSWORD)


def test_nonexistent_email_and_wrong_password_produce_the_same_error(db_session):
    email = _unique_email()
    service = _service(db_session)
    service.register(email, VALID_PASSWORD)

    with pytest.raises(InvalidCredentialsError) as wrong_password_exc:
        service.login(email, "wrong password")
    with pytest.raises(InvalidCredentialsError) as nonexistent_exc:
        service.login("nobody-registered@example.com", VALID_PASSWORD)

    assert str(wrong_password_exc.value) == str(nonexistent_exc.value) == "Invalid email or password."


def test_login_with_inactive_account_fails(db_session):
    email = _unique_email()
    repo = UserRepository(db_session)
    user = repo.create(User(email=email, password_hash=hash_password(VALID_PASSWORD), role="analyst", is_active=False))

    with pytest.raises(InvalidCredentialsError):
        _service(db_session).login(email, VALID_PASSWORD)
    assert user.is_active is False


def test_inactive_account_and_invalid_credentials_produce_the_same_error(db_session):
    email = _unique_email()
    repo = UserRepository(db_session)
    repo.create(User(email=email, password_hash=hash_password(VALID_PASSWORD), role="analyst", is_active=False))
    service = _service(db_session)

    with pytest.raises(InvalidCredentialsError) as inactive_exc:
        service.login(email, VALID_PASSWORD)
    with pytest.raises(InvalidCredentialsError) as bad_password_exc:
        service.login("nobody-registered-either@example.com", VALID_PASSWORD)

    assert str(inactive_exc.value) == str(bad_password_exc.value) == "Invalid email or password."


def test_login_normalizes_email(db_session):
    email = _unique_email()
    service = _service(db_session)
    service.register(email, VALID_PASSWORD)

    result = service.login(f"  {email.upper()}  ", VALID_PASSWORD)

    assert result.user.email == email


def test_login_with_malformed_stored_hash_fails_safely(db_session):
    """A corrupted/tampered password_hash must never cause login() to
    raise anything other than the standard InvalidCredentialsError --
    verify_password() (Step 11B) already guarantees this; this test
    proves AuthService does not accidentally let a lower-level exception
    escape through its own login() path.
    """
    email = _unique_email()
    repo = UserRepository(db_session)
    # "$argon2id$corrupted-not-a-real-hash" still satisfies the DB's
    # prefix-only CHECK constraint (see Step 11B) while being an
    # otherwise-malformed Argon2id PHC string, so this can be committed
    # for real and read back fresh by login()'s own get_by_email() call.
    user = repo.create(
        User(email=email, password_hash=hash_password(VALID_PASSWORD), role="analyst")
    )
    user.password_hash = "$argon2id$corrupted-not-a-real-hash"
    db_session.commit()

    with pytest.raises(InvalidCredentialsError):
        _service(db_session).login(email, VALID_PASSWORD)


def test_login_creates_exactly_one_refresh_token_row_with_a_fresh_family(db_session):
    email = _unique_email()
    service = _service(db_session)
    service.register(email, VALID_PASSWORD)

    result = service.login(email, VALID_PASSWORD)

    rows = list(db_session.scalars(select(RefreshToken).where(RefreshToken.user_id == result.user.id)))
    assert len(rows) == 1
    assert rows[0].revoked_at is None
    assert rows[0].replaced_by_id is None


def test_two_separate_logins_create_two_separate_families(db_session):
    email = _unique_email()
    service = _service(db_session)
    service.register(email, VALID_PASSWORD)

    first = service.login(email, VALID_PASSWORD)
    second = service.login(email, VALID_PASSWORD)

    rows = list(db_session.scalars(select(RefreshToken).where(RefreshToken.user_id == first.user.id)))
    family_ids = {r.family_id for r in rows}
    assert len(rows) == 2
    assert len(family_ids) == 2
    assert first.refresh_token != second.refresh_token


# =============================================================================
# Security / password handling
# =============================================================================


def test_registration_never_leaks_password_via_exception(db_session):
    secret = "UNIQUE_MARKER_PASSWORD_login_leak_test"
    with pytest.raises(PasswordTooShortError) as exc_info:
        _service(db_session).register(_unique_email(), secret[:5])

    assert secret not in str(exc_info.value)


def test_login_never_leaks_password_via_exception(db_session):
    email = _unique_email()
    service = _service(db_session)
    service.register(email, VALID_PASSWORD)
    secret = "UNIQUE_MARKER_WRONG_PASSWORD_9f21"

    with pytest.raises(InvalidCredentialsError) as exc_info:
        service.login(email, secret)

    assert secret not in str(exc_info.value)


def test_registration_cannot_create_admin_role(db_session):
    """AuthService.register() has no `role` parameter at all -- this
    test documents that the service's own signature makes privilege
    escalation through registration structurally impossible, not merely
    discouraged.
    """
    import inspect

    assert "role" not in inspect.signature(AuthService.register).parameters
