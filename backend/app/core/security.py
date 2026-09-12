"""Identity foundation utilities: password hashing and email
normalization (Step 11B).

Foundation only. No login/registration/session/token logic exists yet —
see app.models.user for the User model this supports, and Step 11A's
approved architecture for what later steps will add (JWT issuance in a
token-implementation step, not here). Everything in this module is a
stateless, pure function: nothing here touches the database, a request,
or a session.

Password hashing: Argon2id, via argon2-cffi's PasswordHasher, using the
library's own recommended default cost parameters (time_cost/memory_cost/
parallelism) rather than hand-tuning them — there is no AMNIX-specific
reason yet to deviate from the library's own security recommendations,
and inventing custom parameters without a concrete performance/threat
justification would be exactly the kind of premature complexity this
project avoids elsewhere. `type=Type.ID` is passed explicitly rather
than relying on the library's default, so this module's behavior does
not silently change if a future argon2-cffi version ever changes its
default hash type.

Password validation: MIN_PASSWORD_LENGTH is the one rule this step
establishes. Deliberately no composition rules (uppercase/lowercase/
digit/symbol requirements) — per NIST 800-63B guidance, composition
rules push users toward predictable patterns without meaningfully
improving security; length is the dominant factor. No breached-password
checking either — that requires an external data source/network call,
which is out of scope for a foundation step. validate_password_length()
is the one reusable boundary a future registration flow (Step 11C)
should call — it must not be duplicated elsewhere.

Email normalization: normalize_email() is the single canonical rule
(strip surrounding whitespace, lowercase) for turning user-submitted
email text into the form User.email uniqueness is compared against. No
Unicode normalization (e.g. NFC) is applied — AMNIX has no established
policy requiring it anywhere else (see app.services.copilot_audit_
service's identical stance on not normalizing Unicode in question text),
and inventing one here would be a new, undirected decision. This
function has no automatic caller yet in this step (there is no
registration endpoint/service to wire it into) — it is the designated
boundary a future User-creation path must call before constructing a
User instance; app.repositories.user.UserRepository.create() does not
call it itself, matching how AlertRepository.create()/SecurityEvent
Repository.create() also perform no validation or transformation on
their input, leaving that to the service/schema layer above them.
"""

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHash, VerificationError, VerifyMismatchError

MIN_PASSWORD_LENGTH = 12

_hasher = PasswordHasher(type=Type.ID)


class PasswordTooShortError(ValueError):
    def __init__(self, minimum_length: int = MIN_PASSWORD_LENGTH) -> None:
        self.minimum_length = minimum_length
        super().__init__(f"Password must be at least {minimum_length} characters long.")


def normalize_email(email: str) -> str:
    """The single canonical rule for User.email: strip surrounding
    whitespace, then lowercase. Must be applied before evaluating
    uniqueness or looking up an existing User by email — see this
    module's docstring for exactly where that boundary is.
    """
    return email.strip().lower()


def validate_password_length(password: str) -> None:
    """Raise PasswordTooShortError if `password` is shorter than
    MIN_PASSWORD_LENGTH. The only password-validation rule this step
    establishes — see this module's docstring for why no composition
    rules are added.
    """
    if len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordTooShortError()


def hash_password(password: str) -> str:
    """Hash `password` with Argon2id. Never logs or returns the
    plaintext. The returned string is a complete, self-describing
    Argon2id PHC-format hash (algorithm/version/cost parameters/salt/
    hash all encoded together, always starting with "$argon2id$") — no
    separate salt or parameter storage is needed alongside it.
    """
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """True if `password` matches `password_hash`, otherwise False.
    Never raises — a wrong password and a malformed/tampered hash are
    both simply "not a match", so a future login endpoint can treat
    every failure identically without needing to catch argon2-specific
    exceptions itself, and without leaking *why* verification failed
    (wrong password vs. corrupted hash) to anything upstream.
    """
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHash):
        return False
