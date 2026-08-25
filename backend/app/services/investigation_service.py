"""InvestigationEngine: builds a deterministic InvestigationContext from
an Alert and its associated SecurityEvents.

Security note: every piece of telemetry handled here (hostnames,
usernames, command lines, ...) originates from untrusted sources. This
module only ever treats it as data — formatted into strings and JSON,
never executed, evaluated, or followed as a command/URL/script. A future
AI Copilot consuming InvestigationContext as an LLM prompt must apply
the same discipline: this content is attacker-influenceable and must be
treated as untrusted data, not instructions.
"""

from datetime import datetime, timezone

from app.models.alert import Alert
from app.models.security_event import SecurityEvent
from app.schemas.alert import AlertRead
from app.schemas.investigation import (
    InvestigationContext,
    InvestigationEntities,
    InvestigationSummary,
    TimelineEntry,
)


class InvestigationEngine:
    """Computes an InvestigationContext on demand.

    Stateless and deterministic: the same Alert + SecurityEvent data
    always produces the same context. Never persists anything and never
    mutates the Alert — status changes remain an explicit analyst
    action, never a side effect of viewing an investigation.
    """

    def build_context(self, alert: Alert) -> InvestigationContext:
        related_events = self._gather_related_events(alert)
        timeline = self._build_timeline(related_events)
        entities = self._extract_entities(related_events)
        summary = self._build_summary(alert, timeline, entities)

        return InvestigationContext(
            alert=AlertRead.model_validate(alert),
            timeline=timeline,
            entities=entities,
            summary=summary,
            generated_at=datetime.now(timezone.utc),
        )

    @staticmethod
    def _gather_related_events(alert: Alert) -> list[SecurityEvent]:
        """Events considered part of this investigation.

        Currently just the SecurityEvents directly associated with the
        Alert. This is deliberately isolated as its own step so a future
        version can broaden "related" (e.g. correlate by shared
        host/user/IP within a time window) without touching timeline,
        entity, or summary construction.
        """
        return list(alert.security_events)

    @staticmethod
    def _build_timeline(events: list[SecurityEvent]) -> list[TimelineEntry]:
        # event_timestamp is the primary ordering field; event id (a
        # real total order, not just string-comparable) is the
        # deterministic tie-breaker when timestamps are equal.
        ordered = sorted(events, key=lambda e: (e.event_timestamp, e.id))
        return [
            TimelineEntry(
                event_id=event.id,
                event_timestamp=event.event_timestamp,
                event_type=event.event_type,
                source=event.source,
                hostname=event.hostname,
                username=event.username,
                source_ip=event.source_ip,
                destination_ip=event.destination_ip,
                process_name=event.process_name,
                command_line=event.command_line,
            )
            for event in ordered
        ]

    @staticmethod
    def _extract_entities(events: list[SecurityEvent]) -> InvestigationEntities:
        hostnames = {event.hostname for event in events if event.hostname}
        usernames = {event.username for event in events if event.username}
        source_ips = {str(event.source_ip) for event in events if event.source_ip is not None}
        destination_ips = {
            str(event.destination_ip) for event in events if event.destination_ip is not None
        }
        process_names = {event.process_name for event in events if event.process_name}
        file_hashes = {event.file_hash for event in events if event.file_hash}

        return InvestigationEntities(
            hostnames=sorted(hostnames),
            usernames=sorted(usernames),
            source_ips=sorted(source_ips),
            destination_ips=sorted(destination_ips),
            process_names=sorted(process_names),
            file_hashes=sorted(file_hashes),
        )

    @staticmethod
    def _build_summary(
        alert: Alert, timeline: list[TimelineEntry], entities: InvestigationEntities
    ) -> InvestigationSummary:
        event_count = len(timeline)
        first_event_at = timeline[0].event_timestamp if timeline else None
        last_event_at = timeline[-1].event_timestamp if timeline else None
        timespan_seconds = (
            (last_event_at - first_event_at).total_seconds()
            if first_event_at is not None and last_event_at is not None
            else None
        )

        text = _render_summary_text(
            alert=alert,
            event_count=event_count,
            entities=entities,
            timespan_seconds=timespan_seconds,
        )

        return InvestigationSummary(
            text=text,
            event_count=event_count,
            unique_host_count=len(entities.hostnames),
            unique_user_count=len(entities.usernames),
            timespan_seconds=timespan_seconds,
            first_event_at=first_event_at,
            last_event_at=last_event_at,
        )


def _render_summary_text(
    *,
    alert: Alert,
    event_count: int,
    entities: InvestigationEntities,
    timespan_seconds: float | None,
) -> str:
    sentences = [f"Alert '{alert.title}' was generated by rule '{alert.rule_id}'."]

    involves_parts = []
    if entities.usernames:
        involves_parts.append(_describe_list("user", entities.usernames))
    if entities.hostnames:
        involves_parts.append(_describe_list("host", entities.hostnames))
    if involves_parts:
        sentences.append("It involves " + " and ".join(involves_parts) + ".")

    event_word = "event" if event_count == 1 else "events"
    span_clause = ""
    if timespan_seconds is not None and timespan_seconds > 0:
        span_clause = f" spanning {_format_duration(timespan_seconds)}"
    sentences.append(f"The alert contains {event_count} related security {event_word}{span_clause}.")

    return " ".join(sentences)


def _describe_list(noun: str, values: list[str]) -> str:
    label = noun if len(values) == 1 else f"{noun}s"
    if len(values) == 1:
        joined = values[0]
    elif len(values) == 2:
        joined = f"{values[0]} and {values[1]}"
    else:
        joined = ", ".join(values[:-1]) + f", and {values[-1]}"
    return f"{label} {joined}"


def _format_duration(seconds: float) -> str:
    total_seconds = int(seconds)
    if total_seconds < 60:
        return f"{total_seconds} second{'s' if total_seconds != 1 else ''}"

    minutes, _ = divmod(total_seconds, 60)
    if minutes < 60:
        return f"{minutes} minute{'s' if minutes != 1 else ''}"

    hours, remaining_minutes = divmod(minutes, 60)
    return f"{hours} hour{'s' if hours != 1 else ''} {remaining_minutes} minute{'s' if remaining_minutes != 1 else ''}"
