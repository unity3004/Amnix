"""Suspicious PowerShell process execution detection.

Flags PowerShell process executions whose command line contains a
specific, curated set of indicators commonly associated with malicious
use (hidden-window execution, execution-policy bypass, in-memory
download-and-execute cradles). Merely running PowerShell, or running it
with an ordinary command line, does not trigger this rule.
"""

from collections.abc import Sequence

from app.detections.base import (
    PROCESS_CREATION_EVENT_TYPE,
    DetectionRule,
    is_powershell_process,
    truncate_for_scanning,
)
from app.models.security_event import SecurityEvent
from app.schemas.detection import DetectionConfidence, DetectionResult, DetectionSeverity

# Each entry is a lowercase literal substring, not a regex. Plain
# substring containment checks are O(n) in the input length, cannot
# backtrack, and are easy to reason about and extend.
SUSPICIOUS_COMMAND_LINE_INDICATORS: tuple[str, ...] = (
    "-windowstyle hidden",
    "-w hidden",
    "-executionpolicy bypass",
    "-ep bypass",
    "downloadstring",
    "downloadfile",
    "invoke-expression",
    "iex(",
    "iex (",
    "-noninteractive",
)


class SuspiciousPowerShellDetectionRule(DetectionRule):
    """Detects PowerShell execution with command-line indicators of
    malicious use. Requires both a PowerShell process AND at least one
    curated indicator — running PowerShell alone is not suspicious.
    """

    rule_id = "suspicious_powershell_execution"
    name = "Suspicious PowerShell Execution"
    description = (
        "Detects PowerShell process executions whose command line "
        "contains indicators commonly associated with malicious use, "
        "such as hidden-window execution, execution-policy bypass, or "
        "in-memory download-and-execute cradles."
    )
    severity = DetectionSeverity.MEDIUM
    confidence = DetectionConfidence.MEDIUM

    def evaluate(self, events: Sequence[SecurityEvent]) -> list[DetectionResult]:
        results: list[DetectionResult] = []
        for event in events:
            matched = self._matched_indicators(event)
            if matched:
                results.append(self._build_detection(event, matched))
        return results

    @staticmethod
    def _matched_indicators(event: SecurityEvent) -> list[str]:
        if (event.event_type or "").strip().lower() != PROCESS_CREATION_EVENT_TYPE:
            return []
        if not is_powershell_process(event.process_name):
            return []
        command_line = truncate_for_scanning(event.command_line).lower()
        if not command_line:
            return []
        return [indicator for indicator in SUSPICIOUS_COMMAND_LINE_INDICATORS if indicator in command_line]

    def _build_detection(self, event: SecurityEvent, matched_indicators: list[str]) -> DetectionResult:
        evidence = {
            "process_name": event.process_name,
            "command_line": event.command_line,
            "matched_indicators": matched_indicators,
            "hostname": event.hostname,
            "username": event.username,
        }
        return self._build_result(
            title=f"Suspicious PowerShell execution on {event.hostname or 'unknown host'}",
            description=(
                "PowerShell was executed with command-line indicators commonly "
                f"associated with malicious use: {', '.join(matched_indicators)}."
            ),
            evidence=evidence,
            related_event_ids=[event.id],
        )
