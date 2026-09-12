"""UserService: administrative User lifecycle operations (Step 11G).

AMNIX's first real admin-only capability: an admin enabling or disabling
another user's account (User.is_active). This is deliberately narrow —
see the Step 11G final report for the full discovery process. Explicitly
out of scope here, each a separate future design decision: role changes
(analyst <-> admin), password administration, user deletion, and user
listing/enumeration. This service does exactly one thing.

Built on Step 11B's UserRepository unmodified apart from the new save()
method (mirrors AlertRepository.save()'s exact shape) — no new
persistence primitive, no raw SQL, no authorization logic. Authorization
(who may call this) is entirely the route layer's job via
app.api.dependencies.require_admin (Step 11F); this service only knows
IT IS BEING ASKED to change a target account's active state and enforces
the one business invariant that belongs here (see
CannotModifyOwnAccountError).
"""

import uuid

from app.models.user import User
from app.repositories.user import UserRepository


class UserServiceError(Exception):
    """Base class for every error UserService raises."""


class UserNotFoundError(UserServiceError):
    def __init__(self, user_id: uuid.UUID) -> None:
        self.user_id = user_id
        super().__init__(f"User '{user_id}' not found")


class CannotModifyOwnAccountError(UserServiceError):
    """Raised when an admin's request targets their own account.

    This is Step 11G's chosen self-disablement invariant: rather than
    allow self-disablement and separately build "last active admin"
    protection (which requires counting active admins and is its own
    piece of account-governance policy), self-targeting is rejected
    outright. That single rule makes the last-admin problem
    unreachable through this endpoint by construction — an admin can
    never reduce the active-admin count via their own account through
    this operation, so there is nothing further to guard here. A
    determined admin can still disable every OTHER admin account, which
    this step deliberately does not attempt to prevent (see the final
    report's risks/limitations section) — solving that fully requires
    real account-governance policy, out of scope for the first
    admin-only operation.
    """

    def __init__(self) -> None:
        super().__init__("Admins cannot change their own account status.")


class UserService:
    def __init__(self, repository: UserRepository) -> None:
        self._repository = repository

    def set_active_status(self, *, acting_admin_id: uuid.UUID, target_user_id: uuid.UUID, is_active: bool) -> User:
        """Enable or disable `target_user_id`'s account, persisting
        immediately. The normal, standalone entry point — unchanged in
        behavior/contract since Step 11G. Idempotent: setting an
        already-active account active (or an already-inactive account
        inactive) succeeds and simply re-saves the same value — this is
        a plain field assignment, not a state-machine transition like
        Alert.status (see app.services.alert_lifecycle), so there is no
        notion of an "invalid" target state to reject.

        Only ever mutates `is_active`. `role`, `email`, and
        `password_hash` are never read or written by this method.
        """
        user, _previous_is_active = self.prepare_active_status_change(
            acting_admin_id=acting_admin_id, target_user_id=target_user_id, is_active=is_active
        )
        return self._repository.save(user)

    def prepare_active_status_change(
        self, *, acting_admin_id: uuid.UUID, target_user_id: uuid.UUID, is_active: bool
    ) -> tuple[User, bool]:
        """Step 11M: validates and mutates the target User's `is_active`
        IN MEMORY ONLY — deliberately does not call
        UserRepository.save() (which commits), so this User row remains
        merely dirty-tracked in the session, not yet persisted.

        Exists as a separate, public method (rather than being inlined
        into set_active_status() above) specifically so
        app.services.admin_audit_service.AdminAuditService can perform
        this exact same validation/mutation and then commit it in the
        SAME database transaction as a new AdminAudit row it constructs
        — true atomicity between the user-state mutation and its durable
        audit record, achieved without changing set_active_status()'s
        own existing, already-tested behavior at all (see that method's
        own docstring: it still persists immediately, exactly as before
        Step 11M).

        Returns the mutated (not yet persisted) User together with its
        pre-mutation `is_active` value — the caller needs the "before"
        state to record it, and this is the only place that value is
        ever read, before it is overwritten.
        """
        if target_user_id == acting_admin_id:
            raise CannotModifyOwnAccountError()

        user = self._repository.get_by_id(target_user_id)
        if user is None:
            raise UserNotFoundError(target_user_id)

        previous_is_active = user.is_active
        user.is_active = is_active
        return user, previous_is_active
