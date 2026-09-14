"""CaseService: the persistent SOC Case domain's business logic (Step
12R, architecture approved in Step 12Q).

Owns every business rule for Case: creation, update, lifecycle
transitions, ownership authorization, alert linking/unlinking, note
creation, and -- critically -- the atomic mutation+audit commit pattern
for every one of those (except note creation, which is never audited;
see app.models.case_note's own docstring).

============================================================
THE TRANSACTIONAL GUARANTEE -- reused, not reinvented
============================================================

This service uses the EXACT technique proven by
app.services.admin_audit_service.AdminAuditService (see that module's
own docstring for the full write-up): the primary mutation is prepared
IN MEMORY ONLY (repository `..._without_commit()` methods add/delete
rows on the shared Session without committing), the corresponding
CaseAudit row(s) are added to the SAME session the same way, and this
service issues exactly ONE db.commit() covering everything. Either the
whole unit of work lands together, or (on any commit-time failure) the
whole thing rolls back -- see `_commit()` below, which mirrors
AdminAuditService.change_user_status()'s own try/except/rollback/reraise
line for line.

============================================================
ACTOR RESOLUTION
============================================================

Every actor identity this service ever records (`created_by`,
`actor_user_id`, `linked_by`, `author_id`) is passed in by the API layer
as a plain uuid.UUID/AuthenticatedUser ALREADY resolved from the
authenticated request (app.api.dependencies.get_current_user) -- this
service never reads a request, a header, or a body field to determine
"who is doing this". Combined with the fact that none of the Pydantic
input schemas in app.schemas.case even have an actor-shaped field, actor
spoofing is unreachable by construction, not merely disallowed by
convention.

============================================================
CONCURRENCY
============================================================

No optimistic-locking version column exists (Step 12Q, approved, "do
not overengineer"). Every lifecycle/ownership mutation re-reads the
Case's CURRENT status/owner_id from the database at the start of the
call and validates the requested change against that live value -- a
second, slightly-stale concurrent request naturally fails (409/403) when
it re-validates against what is now the *actual* current state, rather
than trusting a client-asserted "previous" value. Duplicate alert
linking is additionally protected at the database level by
CaseAlert's own composite primary key.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.api.dependencies import AuthenticatedUser
from app.models.alert import Alert
from app.models.case import Case, CaseAlert
from app.models.case_audit import CaseAudit
from app.models.case_note import CaseNote
from app.repositories.alert import AlertRepository
from app.repositories.case import CaseRepository
from app.repositories.case_alert import CaseAlertRepository
from app.repositories.case_audit import CaseAuditRepository
from app.repositories.case_note import CaseNoteRepository
from app.repositories.user import UserRepository
from app.schemas.case import CaseAuditAction, CasePriority, CaseStatus
from app.services.alert_service import AlertNotFoundError
from app.services.case_lifecycle import assert_valid_transition

# Ascending impact, mirroring the frontend's own SEVERITY_PRIORITY_RANK
# convention (features/alerts/priority.ts) -- higher number = more severe.
_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class CaseServiceError(Exception):
    """Base class for every error CaseService raises."""


class CaseNotFoundError(CaseServiceError):
    def __init__(self, case_id: uuid.UUID) -> None:
        self.case_id = case_id
        super().__init__(f"Case '{case_id}' not found")


class AlertAlreadyLinkedError(CaseServiceError):
    def __init__(self, case_id: uuid.UUID, alert_id: uuid.UUID) -> None:
        self.case_id = case_id
        self.alert_id = alert_id
        super().__init__(f"Alert '{alert_id}' is already linked to case '{case_id}'")


class AlertNotLinkedError(CaseServiceError):
    def __init__(self, case_id: uuid.UUID, alert_id: uuid.UUID) -> None:
        self.case_id = case_id
        self.alert_id = alert_id
        super().__init__(f"Alert '{alert_id}' is not linked to case '{case_id}'")


class ClosureReasonRequiredError(CaseServiceError):
    def __init__(self) -> None:
        super().__init__("closure_reason is required and must not be blank when closing a case")


class CaseOwnerNotFoundError(CaseServiceError):
    def __init__(self, owner_id: uuid.UUID) -> None:
        self.owner_id = owner_id
        super().__init__(f"User '{owner_id}' not found")


class InactiveCaseOwnerError(CaseServiceError):
    def __init__(self, owner_id: uuid.UUID) -> None:
        self.owner_id = owner_id
        super().__init__(f"User '{owner_id}' is not active")


class CaseOwnershipAuthorizationError(CaseServiceError):
    """Raised when a non-admin analyst attempts an owner mutation outside
    the two rules they are permitted (self-assign an unowned case;
    release their own case) -- see change_owner()'s own docstring.
    """

    def __init__(self) -> None:
        super().__init__("You may only self-assign an unowned case or release a case you own.")


def _fmt_user(user_id: uuid.UUID | None) -> str | None:
    return str(user_id) if user_id is not None else None


class CaseService:
    def __init__(
        self,
        db: Session,
        case_repository: CaseRepository,
        case_alert_repository: CaseAlertRepository,
        case_audit_repository: CaseAuditRepository,
        case_note_repository: CaseNoteRepository,
        alert_repository: AlertRepository,
        user_repository: UserRepository,
    ) -> None:
        self._db = db
        self._cases = case_repository
        self._case_alerts = case_alert_repository
        self._audits = case_audit_repository
        self._notes = case_note_repository
        self._alerts = alert_repository
        self._users = user_repository

    def _commit(self) -> None:
        try:
            self._db.commit()
        except Exception:
            self._db.rollback()
            raise

    def _require_case(self, case_id: uuid.UUID) -> Case:
        case = self._cases.get_by_id(case_id)
        if case is None:
            raise CaseNotFoundError(case_id)
        return case

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get_case(self, case_id: uuid.UUID) -> Case:
        return self._require_case(case_id)

    def list_cases(
        self,
        *,
        limit: int,
        offset: int,
        status: CaseStatus | None = None,
        priority: CasePriority | None = None,
        owner_id: uuid.UUID | None = None,
    ) -> list[Case]:
        return self._cases.list(
            limit=limit,
            offset=offset,
            status=status.value if status is not None else None,
            priority=priority.value if priority is not None else None,
            owner_id=owner_id,
        )

    def list_alerts(self, case_id: uuid.UUID) -> list[Alert]:
        self._require_case(case_id)
        return self._case_alerts.list_alerts_for_case(case_id)

    def list_cases_for_alert(self, alert_id: uuid.UUID, *, limit: int, offset: int) -> list[Case]:
        """Step 12V: the authoritative reverse relationship -- which
        Cases (if any) currently cite this Alert. Existence-checks the
        Alert the exact same way link_alert() below already does
        (self._alerts.get_by_id, raising the same AlertNotFoundError the
        API layer already knows how to turn into a 404) so a nonexistent
        alert_id is never confused with "this alert exists but has zero
        linked cases" (that case returns an empty list, a normal 200).
        Purely a read -- no CaseAudit row, no mutation of any kind.
        """
        alert = self._alerts.get_by_id(alert_id)
        if alert is None:
            raise AlertNotFoundError(alert_id)
        return self._case_alerts.list_cases_for_alert(alert_id, limit=limit, offset=offset)

    def list_audits(self, case_id: uuid.UUID, *, limit: int, offset: int) -> list[CaseAudit]:
        self._require_case(case_id)
        return self._audits.list_for_case(case_id, limit=limit, offset=offset)

    def list_notes(self, case_id: uuid.UUID, *, limit: int, offset: int) -> list[CaseNote]:
        self._require_case(case_id)
        return self._notes.list_for_case(case_id, limit=limit, offset=offset)

    def derive_severity(self, case_id: uuid.UUID) -> str | None:
        """Max severity among this case's currently-linked alerts, or
        None if no alerts are linked -- never a default/invented value.
        Computed fresh on every call, never stored (see app.models.case's
        own docstring for why Case has no `severity` column at all).
        """
        alerts = self._case_alerts.list_alerts_for_case(case_id)
        if not alerts:
            return None
        return max((a.severity for a in alerts), key=lambda s: _SEVERITY_RANK[s])

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------

    def create_case(self, *, title: str, description: str, priority: CasePriority, created_by: uuid.UUID) -> Case:
        case = Case(
            title=title,
            description=description,
            priority=priority.value,
            status=CaseStatus.OPEN.value,
            created_by=created_by,
        )
        self._cases.create_without_commit(case)
        # Flush (not commit) so the server-generated id/case_number are
        # populated before building the CASE_CREATED audit row that
        # references case.id -- still inside the same uncommitted
        # transaction, so a later failure still rolls both back together.
        self._db.flush()

        audit = CaseAudit(
            case_id=case.id,
            actor_user_id=created_by,
            action=CaseAuditAction.CASE_CREATED.value,
            previous_value=None,
            new_value=f"case_number={case.case_number}, title={title!r}, priority={priority.value!r}",
        )
        self._audits.create_without_commit(audit)

        self._commit()
        self._db.refresh(case)
        return case

    # ------------------------------------------------------------------
    # Update (title/description/priority)
    # ------------------------------------------------------------------

    def update_case(
        self,
        case_id: uuid.UUID,
        *,
        title: str | None,
        description: str | None,
        priority: CasePriority | None,
        actor_id: uuid.UUID,
    ) -> Case:
        """Updates only the fields actually provided (None = unchanged).
        Creates one CaseAudit row per field whose value actually changes
        -- never a generic CASE_UPDATED, never an audit row for a field
        that was submitted but equals its current value. If nothing
        actually changes, no audit row is created at all and the
        unchanged Case is returned as a normal 200 -- this differs from
        the dedicated status/owner endpoints (which always audit every
        successful call, matching AdminAudit's own per-invocation
        philosophy for a single-purpose toggle) because this is a
        multi-field endpoint where a caller may legitimately submit only
        the fields they want to confirm, not necessarily change.
        """
        case = self._require_case(case_id)
        audits: list[CaseAudit] = []

        if title is not None and title != case.title:
            audits.append(
                CaseAudit(
                    case_id=case.id,
                    actor_user_id=actor_id,
                    action=CaseAuditAction.CASE_TITLE_CHANGED.value,
                    previous_value=case.title,
                    new_value=title,
                )
            )
            case.title = title

        if description is not None and description != case.description:
            audits.append(
                CaseAudit(
                    case_id=case.id,
                    actor_user_id=actor_id,
                    action=CaseAuditAction.CASE_DESCRIPTION_CHANGED.value,
                    previous_value=case.description,
                    new_value=description,
                )
            )
            case.description = description

        if priority is not None and priority.value != case.priority:
            audits.append(
                CaseAudit(
                    case_id=case.id,
                    actor_user_id=actor_id,
                    action=CaseAuditAction.CASE_PRIORITY_CHANGED.value,
                    previous_value=case.priority,
                    new_value=priority.value,
                )
            )
            case.priority = priority.value

        if not audits:
            # Nothing changed -- no-op success, no fabricated audit.
            return case

        for audit in audits:
            self._audits.create_without_commit(audit)

        self._commit()
        self._db.refresh(case)
        return case

    # ------------------------------------------------------------------
    # Status transitions
    # ------------------------------------------------------------------

    def change_status(
        self, case_id: uuid.UUID, *, new_status: CaseStatus, closure_reason: str | None, actor_id: uuid.UUID
    ) -> Case:
        """Loads the LIVE case, validates the requested transition
        against its CURRENT (not client-asserted) status, and commits the
        mutation atomically with exactly one audit row. See
        app.services.case_lifecycle for the transition table and this
        module's own docstring for the concurrency reasoning.
        """
        case = self._require_case(case_id)
        current_status = CaseStatus(case.status)
        assert_valid_transition(current_status, new_status)

        previous_status_value = case.status

        if new_status is CaseStatus.CLOSED:
            if closure_reason is None or not closure_reason.strip():
                raise ClosureReasonRequiredError()
            reason = closure_reason.strip()
            case.status = new_status.value
            case.closed_at = datetime.now(timezone.utc)
            case.closure_reason = reason
            action = CaseAuditAction.CASE_CLOSED
            new_value = reason
        elif current_status is CaseStatus.CLOSED and new_status is CaseStatus.INVESTIGATING:
            case.status = new_status.value
            case.closed_at = None
            case.closure_reason = None
            action = CaseAuditAction.CASE_REOPENED
            new_value = new_status.value
        else:
            case.status = new_status.value
            action = CaseAuditAction.CASE_STATUS_CHANGED
            new_value = new_status.value

        audit = CaseAudit(
            case_id=case.id,
            actor_user_id=actor_id,
            action=action.value,
            previous_value=previous_status_value,
            new_value=new_value,
        )
        self._audits.create_without_commit(audit)

        self._commit()
        self._db.refresh(case)
        return case

    # ------------------------------------------------------------------
    # Ownership
    # ------------------------------------------------------------------

    def change_owner(self, case_id: uuid.UUID, *, new_owner_id: uuid.UUID | None, actor: AuthenticatedUser) -> Case:
        """Object-level authorization (Step 12Q, approved):

        Admin: may assign/reassign/release any case to/from any active
        user, unconditionally.

        Analyst: may ONLY
          - self-assign a currently-UNOWNED case (case.owner_id is None
            AND new_owner_id == actor.id), or
          - release a case THEY OWN (case.owner_id == actor.id AND
            new_owner_id is None).
        Any other analyst-requested change (assigning an unowned case to
        someone else, reassigning/taking another analyst's case) raises
        CaseOwnershipAuthorizationError.

        If `new_owner_id` is not None, the target user must exist and be
        active AT ASSIGNMENT TIME (a later deactivation does not
        retroactively clear owner_id -- see app.models.case's own
        docstring).

        Every successful call creates exactly one CASE_OWNER_CHANGED
        audit row, even a no-op reassignment to the same owner --
        matching AdminAudit's own "audit every successful invocation"
        philosophy for this single-purpose endpoint (unlike the
        multi-field update_case(), which only audits actual changes).
        """
        case = self._require_case(case_id)
        current_owner_id = case.owner_id

        if actor.role != "admin":
            self_assign = current_owner_id is None and new_owner_id == actor.id
            release_own = current_owner_id == actor.id and new_owner_id is None
            if not (self_assign or release_own):
                raise CaseOwnershipAuthorizationError()

        if new_owner_id is not None:
            target_user = self._users.get_by_id(new_owner_id)
            if target_user is None:
                raise CaseOwnerNotFoundError(new_owner_id)
            if not target_user.is_active:
                raise InactiveCaseOwnerError(new_owner_id)

        case.owner_id = new_owner_id

        audit = CaseAudit(
            case_id=case.id,
            actor_user_id=actor.id,
            action=CaseAuditAction.CASE_OWNER_CHANGED.value,
            previous_value=_fmt_user(current_owner_id),
            new_value=_fmt_user(new_owner_id),
        )
        self._audits.create_without_commit(audit)

        self._commit()
        self._db.refresh(case)
        return case

    # ------------------------------------------------------------------
    # Alert linking
    # ------------------------------------------------------------------

    def link_alert(self, case_id: uuid.UUID, *, alert_id: uuid.UUID, actor_id: uuid.UUID) -> CaseAlert:
        self._require_case(case_id)
        alert = self._alerts.get_by_id(alert_id)
        if alert is None:
            raise AlertNotFoundError(alert_id)
        if self._case_alerts.exists(case_id, alert_id):
            raise AlertAlreadyLinkedError(case_id, alert_id)

        link = CaseAlert(case_id=case_id, alert_id=alert_id, linked_by=actor_id)
        self._case_alerts.create_without_commit(link)

        audit = CaseAudit(
            case_id=case_id,
            actor_user_id=actor_id,
            action=CaseAuditAction.CASE_ALERT_LINKED.value,
            related_alert_id=alert_id,
        )
        self._audits.create_without_commit(audit)

        self._commit()
        self._db.refresh(link)
        return link

    def unlink_alert(self, case_id: uuid.UUID, *, alert_id: uuid.UUID, actor_id: uuid.UUID) -> None:
        """The Alert itself is never deleted or otherwise modified --
        only the case_alerts link row is removed.
        """
        self._require_case(case_id)
        link = self._case_alerts.get(case_id, alert_id)
        if link is None:
            raise AlertNotLinkedError(case_id, alert_id)

        self._case_alerts.delete_without_commit(link)

        audit = CaseAudit(
            case_id=case_id,
            actor_user_id=actor_id,
            action=CaseAuditAction.CASE_ALERT_UNLINKED.value,
            related_alert_id=alert_id,
        )
        self._audits.create_without_commit(audit)

        self._commit()

    # ------------------------------------------------------------------
    # Notes
    # ------------------------------------------------------------------

    def add_note(self, case_id: uuid.UUID, *, body: str, actor_id: uuid.UUID) -> CaseNote:
        """No CaseAudit row is created for note authorship -- the note
        itself (author_id + created_at) is already its own authorship
        record. See app.models.case_note's own docstring.
        """
        self._require_case(case_id)
        note = CaseNote(case_id=case_id, author_id=actor_id, body=body)
        return self._notes.create(note)
