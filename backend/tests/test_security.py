"""Unit tests for app.core.security (Step 11B): password hashing,
verification, length validation, and email normalization. Pure
functions, no database required.

Per the Step 11B brief: these tests avoid asserting on Argon2's internal
parameter encoding beyond the stable, documented PHC prefix
("$argon2id$") -- they do not pin exact cost parameters, salt length, or
any other implementation detail the argon2-cffi library owns.
"""

import pytest

from app.core.security import (
    MIN_PASSWORD_LENGTH,
    PasswordTooShortError,
    hash_password,
    normalize_email,
    validate_password_length,
    verify_password,
)

# =============================================================================
# Password hashing
# =============================================================================


def test_hash_password_returns_an_argon2id_hash():
    result = hash_password("correct horse battery staple")

    assert result.startswith("$argon2id$")


def test_verify_password_succeeds_for_the_correct_password():
    password = "correct horse battery staple"
    hashed = hash_password(password)

    assert verify_password(password, hashed) is True


def test_verify_password_fails_for_an_incorrect_password():
    hashed = hash_password("correct horse battery staple")

    assert verify_password("wrong password entirely", hashed) is False


def test_verify_password_fails_safely_for_a_tampered_hash():
    hashed = hash_password("correct horse battery staple")
    tampered = hashed[:-4] + "abcd"

    assert verify_password("correct horse battery staple", tampered) is False


def test_verify_password_fails_safely_for_a_completely_malformed_hash():
    assert verify_password("anything", "not-a-real-hash-at-all") is False


def test_verify_password_does_not_raise_for_malformed_input():
    """Both wrong-password and corrupted-hash cases must be
    indistinguishable "not a match" outcomes to the caller -- neither
    should ever propagate an argon2-specific exception.
    """
    try:
        result = verify_password("x", "$argon2id$garbage")
    except Exception as exc:  # noqa: BLE001 - the point of the test is that nothing escapes
        pytest.fail(f"verify_password raised instead of returning False: {exc!r}")
    assert result is False


# --- security properties ---------------------------------------------------


def test_password_hash_is_not_equal_to_the_plaintext():
    password = "correct horse battery staple"

    assert hash_password(password) != password


def test_password_hash_does_not_contain_the_plaintext():
    password = "UNIQUE_MARKER_PASSWORD_7f3a"

    assert password not in hash_password(password)


def test_repeated_hashing_of_the_same_password_produces_different_hashes():
    """Argon2id salts each hash independently -- two hashes of the same
    password must never be byte-identical.
    """
    password = "correct horse battery staple"

    first = hash_password(password)
    second = hash_password(password)

    assert first != second
    # But both must still independently verify against the same password.
    assert verify_password(password, first) is True
    assert verify_password(password, second) is True


def test_hash_password_never_leaks_the_password_via_exception_text():
    """Best-effort proof that even if hashing a weird input ever raised,
    the password itself would not appear in the exception's own text.
    """
    password = "UNIQUE_MARKER_PASSWORD_9c21\x00withnull"
    try:
        result = hash_password(password)
    except Exception as exc:  # noqa: BLE001
        assert "UNIQUE_MARKER_PASSWORD_9c21" not in str(exc)
    else:
        assert "UNIQUE_MARKER_PASSWORD_9c21" not in result


# =============================================================================
# Password length validation
# =============================================================================


def test_validate_password_length_rejects_values_below_minimum():
    with pytest.raises(PasswordTooShortError):
        validate_password_length("short11ch")  # 9 characters


def test_validate_password_length_rejects_eleven_characters():
    with pytest.raises(PasswordTooShortError):
        validate_password_length("a" * (MIN_PASSWORD_LENGTH - 1))


def test_validate_password_length_accepts_exactly_the_minimum():
    validate_password_length("a" * MIN_PASSWORD_LENGTH)  # must not raise


def test_validate_password_length_accepts_longer_passwords():
    validate_password_length("a" * (MIN_PASSWORD_LENGTH + 20))  # must not raise


def test_password_too_short_error_message_does_not_echo_the_password():
    password = "UNIQUE_SHORT_MARKER"
    try:
        validate_password_length(password[:5])
    except PasswordTooShortError as exc:
        assert password not in str(exc)


# =============================================================================
# Email normalization
# =============================================================================


def test_normalize_email_strips_and_lowercases():
    assert normalize_email(" Analyst@Example.COM ") == "analyst@example.com"


def test_normalize_email_is_idempotent():
    once = normalize_email(" Analyst@Example.COM ")
    twice = normalize_email(once)

    assert once == twice == "analyst@example.com"


def test_normalize_email_leaves_already_canonical_email_unchanged():
    assert normalize_email("analyst@example.com") == "analyst@example.com"
