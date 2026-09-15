"""CopilotAuditService: the application-level API for recording and
retrieving Copilot audit information (see app.models.copilot_audit and
app.repositories.copilot_audit).

Step 10F.3 scope: this service is not yet called from anywhere.
CopilotService.ask()/follow_up() are not touched, there is no API route,
and AI providers/schemas are untouched. Wiring this in is Step 10F.4.

Transaction behavior (see app.repositories.copilot_audit's module
docstring for the repository half of this): CopilotAuditRepository.create()
commits, matching this codebase's one and only transaction-management
convention (every write-repository commits its own unit of work -- see
AlertRepository.create()/.save(), SecurityEventRepository.create()). That
is safe to call from inside CopilotService specifically BECAUSE
CopilotService.ask()/follow_up() are documented, tested, and read-only
with respect to Alert (see copilot_service.py's own docstrings and
test_copilot_service.py's test_does_not_change_alert_status /
test_follow_up_alert_remains_unchanged): at the point a future Step
10F.4 integration would call CopilotAuditService.record(), there is no
other pending, uncommitted Alert mutation in that request's session for
an audit-record commit to inadvertently sweep in. If CopilotService ever
grows a code path that mutates Alert state in the same call, this
invariant must be re-reviewed before wiring the audit write into that
path -- it is not something this layer can guard against on its own
without inventing a second transaction pattern, which the Step 10F.3
brief explicitly rules out.

Alert-existence validation: record() checks the referenced Alert exists
(via a plain AlertRepository.get_by_id() read -- no AlertService
dependency, since only existence, not any Alert business logic, is
needed here) before ever constructing or persisting a CopilotAudit,
mirroring how AlertService.update_status() checks `alert is None` before
proceeding. This also happens to be required by the database's own
foreign-key constraint, but checking first lets Step 10F.3 raise a
specific, typed CopilotAuditAlertNotFoundError instead of letting an
IntegrityError surface.

Step 13D: record() now accepts EITHER `alert_id` OR `case_id` (never
both, never neither -- mirrors app.models.copilot_audit's own
ck_copilot_audits_exactly_one_scope exactly, enforced here first as a
typed CopilotAuditValidationError, the database CHECK constraint remains
defense in depth). Case existence is validated the same
read-only-existence-check way Alert existence already is, via a plain
CaseRepository.get_by_id() read -- no CaseService dependency, since only
existence is needed here.
"""

import hashlib
import logging
import uuid
from collections.abc import Sequence

from sqlalchemy.exc import SQLAlchemyError

from app.models.copilot_audit import CopilotAudit
from app.repositories.alert import AlertRepository
from app.repositories.case import CaseRepository
from app.repositories.copilot_audit import DEFAULT_LIST_LIMIT, CopilotAuditRepository
from app.schemas.ai import CopilotMessage
from app.schemas.copilot_audit import AuditOutcome, AuditRequestType, AuditValidationStatus

logger = logging.getLogger(__name__)

# The only (outcome -> http_status) and (outcome -> allowed validation
# statuses) combinations CopilotService's current two-outcome shape can
# produce -- mirrors app.models.copilot_audit's
# ck_copilot_audits_outcome_http_validation_consistency CHECK exactly, so
# a bad combination is rejected here, as a typed CopilotAuditValidationError,
# before it would otherwise surface as a raw IntegrityError from Postgres.
_EXPECTED_HTTP_STATUS_BY_OUTCOME: dict[AuditOutcome, int] = {
    AuditOutcome.SUCCESS: 200,
    AuditOutcome.FAILURE: 502,
}
_ALLOWED_VALIDATION_STATUSES_BY_OUTCOME: dict[AuditOutcome, frozenset[AuditValidationStatus]] = {
    AuditOutcome.SUCCESS: frozenset({AuditValidationStatus.PASSED}),
    AuditOutcome.FAILURE: frozenset({AuditValidationStatus.FAILED, AuditValidationStatus.NOT_APPLICABLE}),
}

_FINGERPRINT_VERSION = "v1"


class CopilotAuditError(Exception):
    """Base class for every error CopilotAuditService raises."""


class CopilotAuditAlertNotFoundError(CopilotAuditError):
    def __init__(self, alert_id: uuid.UUID) -> None:
        self.alert_id = alert_id
        super().__init__(f"Alert '{alert_id}' not found")


class CopilotAuditCaseNotFoundError(CopilotAuditError):
    def __init__(self, case_id: uuid.UUID) -> None:
        self.case_id = case_id
        super().__init__(f"Case '{case_id}' not found")


class CopilotAuditValidationError(CopilotAuditError):
    """Raised for structurally invalid input this service can catch
    itself before ever touching the database -- e.g. an outcome/
    http_status/validation_status combination the database's own CHECK
    constraint would also reject, or history supplied for an 'ask'
    request. Always constructed with a fixed, descriptive-but-safe
    message; never with raw exception text.
    """


class CopilotAuditPersistenceError(CopilotAuditError):
    """Raised when persistence itself fails for a reason this service
    could not have validated in advance (e.g. a genuine database
    connectivity problem, or a concurrent Alert deletion racing the
    foreign-key check). The original exception is always logged
    server-side and chained via `from exc` for the stack trace, but its
    text is never included in this exception's message -- see this
    class's raise site in record().
    """


class CopilotAuditService:
    def __init__(
        self,
        repository: CopilotAuditRepository,
        alert_repository: AlertRepository,
        case_repository: CaseRepository | None = None,
    ) -> None:
        self._repository = repository
        self._alert_repository = alert_repository
        # Step 13D: optional so every EXISTING caller (CopilotService,
        # its tests, app.api.alerts' own DI wiring) keeps working
        # unmodified -- only CaseCopilotService's DI wiring needs to
        # supply this. record()/list_for_case() raise a clear
        # ValueError (a programming-error signal, not a typed
        # CopilotAuditError an API layer would map to an HTTP response)
        # if a case-scoped call is attempted without it.
        self._case_repository = case_repository

    def record(
        self,
        *,
        alert_id: uuid.UUID | None = None,
        case_id: uuid.UUID | None = None,
        request_type: AuditRequestType,
        provider_name: str,
        model_name: str | None,
        outcome: AuditOutcome,
        validation_status: AuditValidationStatus,
        http_status: int,
        question: str,
        history: Sequence[CopilotMessage] = (),
        duration_ms: int | None = None,
    ) -> CopilotAudit:
        """Typed creation entry point -- the only way to create a
        CopilotAudit through this service. There is no dict-based escape
        hatch: every field is a real parameter with a real type, exactly
        like CopilotAssessment/RecommendedInvestigationAction never
        accept arbitrary dicts either.

        `question`/`history` are used ONLY to compute
        `question_fingerprint` (see compute_fingerprint) and the bounded
        `question_length`/`history_turn_count` size metadata -- their
        content never reaches the CopilotAudit row or this method's
        return value in any other form.

        Step 13D: exactly one of `alert_id`/`case_id` must be supplied --
        mirrors app.models.copilot_audit's own
        ck_copilot_audits_exactly_one_scope; checked here first as a
        typed CopilotAuditValidationError so a caller-side bug never
        reaches the database CHECK constraint as an opaque IntegrityError.
        """
        if (alert_id is None) == (case_id is None):
            raise CopilotAuditValidationError("exactly one of alert_id/case_id must be supplied")

        if alert_id is not None:
            if self._alert_repository.get_by_id(alert_id) is None:
                raise CopilotAuditAlertNotFoundError(alert_id)
        else:
            assert case_id is not None
            if self._case_repository is None:
                raise ValueError("CopilotAuditService was constructed without a case_repository; cannot audit a case-scoped call")
            if self._case_repository.get_by_id(case_id) is None:
                raise CopilotAuditCaseNotFoundError(case_id)

        if http_status != _EXPECTED_HTTP_STATUS_BY_OUTCOME[outcome]:
            raise CopilotAuditValidationError(
                f"http_status {http_status} is not valid for outcome '{outcome.value}' "
                f"(expected {_EXPECTED_HTTP_STATUS_BY_OUTCOME[outcome]})"
            )
        if validation_status not in _ALLOWED_VALIDATION_STATUSES_BY_OUTCOME[outcome]:
            allowed = ", ".join(v.value for v in _ALLOWED_VALIDATION_STATUSES_BY_OUTCOME[outcome])
            raise CopilotAuditValidationError(
                f"validation_status '{validation_status.value}' is not valid for outcome "
                f"'{outcome.value}' (expected one of: {allowed})"
            )
        if request_type in (AuditRequestType.ASK, AuditRequestType.CASE_BRIEF) and history:
            raise CopilotAuditValidationError(f"an '{request_type.value}' request must not include conversation history")
        if duration_ms is not None and duration_ms < 0:
            raise CopilotAuditValidationError("duration_ms must be non-negative")

        fingerprint = self.compute_fingerprint(request_type, question, history)
        history_turn_count = (
            len(history) if request_type in (AuditRequestType.FOLLOW_UP, AuditRequestType.CASE_FOLLOW_UP) else None
        )

        audit = CopilotAudit(
            alert_id=alert_id,
            case_id=case_id,
            request_type=request_type.value,
            provider_name=provider_name,
            model_name=model_name,
            outcome=outcome.value,
            validation_status=validation_status.value,
            http_status=http_status,
            question_fingerprint=fingerprint,
            question_length=len(question),
            history_turn_count=history_turn_count,
            duration_ms=duration_ms,
        )

        try:
            return self._repository.create(audit)
        except SQLAlchemyError as exc:
            logger.exception("Failed to persist CopilotAudit for %s", f"alert {alert_id}" if alert_id else f"case {case_id}")
            raise CopilotAuditPersistenceError("Failed to persist the Copilot audit record.") from exc

    def get_by_id(self, audit_id: uuid.UUID) -> CopilotAudit | None:
        try:
            return self._repository.get_by_id(audit_id)
        except SQLAlchemyError as exc:
            logger.exception("Failed to fetch CopilotAudit %s", audit_id)
            raise CopilotAuditPersistenceError("Failed to retrieve the Copilot audit record.") from exc

    def list_for_alert(
        self, alert_id: uuid.UUID, *, limit: int = DEFAULT_LIST_LIMIT, offset: int = 0
    ) -> list[CopilotAudit]:
        """Step 10F.5: the retrieval half of this service -- read-only,
        alert-scoped (the WHERE alert_id = ... clause lives entirely in
        CopilotAuditRepository.list_for_alert; this method never filters
        in Python), newest-first with a deterministic id tie-break (see
        the repository). `limit`/`offset` bounds are the repository's
        (1..MAX_LIST_LIMIT / >=0) — a caller-supplied value outside that
        range surfaces as CopilotAuditValidationError, not a raw
        ValueError, matching the typed-exception discipline record()
        already establishes. app.api.alerts additionally validates
        limit/offset at the API layer before ever calling this, via
        FastAPI's own Query bounds, so this ValueError path is normally
        unreachable through HTTP -- it remains here as this service's own
        contract for any other caller.
        """
        try:
            return self._repository.list_for_alert(alert_id, limit=limit, offset=offset)
        except ValueError as exc:
            raise CopilotAuditValidationError(str(exc)) from exc
        except SQLAlchemyError as exc:
            logger.exception("Failed to list CopilotAudit records for alert %s", alert_id)
            raise CopilotAuditPersistenceError("Failed to retrieve Copilot audit records.") from exc

    def list_for_case(
        self, case_id: uuid.UUID, *, limit: int = DEFAULT_LIST_LIMIT, offset: int = 0
    ) -> list[CopilotAudit]:
        """Step 13D: the Case-scoped counterpart to list_for_alert --
        identical read-only, bounded, newest-first contract, filtering on
        `case_id` instead of `alert_id`.
        """
        try:
            return self._repository.list_for_case(case_id, limit=limit, offset=offset)
        except ValueError as exc:
            raise CopilotAuditValidationError(str(exc)) from exc
        except SQLAlchemyError as exc:
            logger.exception("Failed to list CopilotAudit records for case %s", case_id)
            raise CopilotAuditPersistenceError("Failed to retrieve Copilot audit records.") from exc

    @staticmethod
    def compute_fingerprint(
        request_type: AuditRequestType, question: str, history: Sequence[CopilotMessage] = ()
    ) -> str:
        """The one canonical fingerprinting strategy -- every caller of
        this service goes through this method; there is no second way to
        compute a question_fingerprint anywhere in AMNIX.

        Canonical encoding (documented here, not just in code, per the
        Step 10F.3 brief):

            v1:<len(rt)>:<rt>:<len(q)>:<q>:<len(h)>:<h>

        where:
          - `rt` is `request_type.value` ("ask" or "follow_up") verbatim.
          - `q` is `question.strip()` -- leading/trailing whitespace is
            removed, but internal whitespace (including internal
            newlines/repeated spaces) is preserved exactly, so two
            questions that only differ in internal spacing are NOT
            treated as identical.
          - `h` is the concatenation, over `history` IN ORDER (order
            matters -- this is not a set), of one length-prefixed segment
            per turn: `<len(turn)>:<turn>` where
            `turn = f"{role.value}:{content.strip()}"` (role is always
            exactly "user" or "assistant" -- a closed vocabulary that can
            never itself contain ":", so no separate prefix is needed for
            it). For an `ask` call, or a `follow_up` call with no prior
            turns, `history` is empty and `h` is simply "" (still
            present, still length-prefixed as `0:`) -- "no history" is
            therefore represented the same deterministic way every time,
            never omitted from the template.
          - every `<len(x)>` is the UTF-8 byte length of `x` (not the
            character count), written in decimal.

        Every component is individually length-prefixed specifically so
        that concatenation is injective (collision-free by construction,
        independent of SHA-256's own collision resistance): two
        different (request_type, question, history) triples can never
        produce the same canonical string merely because a delimiter
        character happened to appear inside a question or a turn's
        content. This is also why `request_type` is embedded first --
        "ask" and "follow_up" are different length-prefixed tokens, so an
        ask() and a follow_up() call can never canonicalize to the same
        string even for byte-identical question text.

        No Unicode normalization (e.g. NFC) is applied -- two different
        Unicode representations of visually-identical text are not
        guaranteed to fingerprint identically. This mirrors how the rest
        of AMNIX treats text (no other component normalizes user-supplied
        text either); it is a deliberate scope limit, not an oversight.

        The result is always a lowercase SHA-256 hex digest (64
        characters), matching app.models.copilot_audit's
        ck_copilot_audits_question_fingerprint_sha256_hex CHECK exactly.
        """
        canonical = _canonicalize(request_type, question, history)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _encode_component(value: str) -> str:
    return f"{len(value.encode('utf-8'))}:{value}"


def _encode_history(history: Sequence[CopilotMessage]) -> str:
    return "".join(_encode_component(f"{turn.role.value}:{turn.content.strip()}") for turn in history)


def _canonicalize(request_type: AuditRequestType, question: str, history: Sequence[CopilotMessage]) -> str:
    return (
        f"{_FINGERPRINT_VERSION}:"
        f"{_encode_component(request_type.value)}:"
        f"{_encode_component(question.strip())}:"
        f"{_encode_component(_encode_history(history))}"
    )
