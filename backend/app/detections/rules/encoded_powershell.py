"""Encoded PowerShell command detection.

Flags PowerShell executions using the -EncodedCommand flag (or its
common -enc abbreviation), frequently used to smuggle obfuscated/base64
payloads past casual log review. Matching is done against literal
command-line flag tokens, not by searching for the word "powershell"
anywhere in the command line.
"""

import re
from collections.abc import Sequence

from app.detections.base import (
    PROCESS_CREATION_EVENT_TYPE,
    DetectionRule,
    is_powershell_process,
    truncate_for_scanning,
)
from app.models.security_event import SecurityEvent
from app.schemas.detection import DetectionConfidence, DetectionResult, DetectionSeverity

# Matches "-enc" or "-encodedcommand" as a whole token, bounded by
# non-alphanumeric characters or the string edges, case-insensitive.
# There are no nested quantifiers and no overlapping alternation — the
# single optional group and fixed-width lookarounds mean this cannot
# exhibit catastrophic backtracking on any input.
_ENCODED_COMMAND_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])-enc(odedcommand)?(?![A-Za-z0-9])", re.IGNORECASE
)


class EncodedPowerShellDetectionRule(DetectionRule):
    """Detects the -EncodedCommand/-enc flag on a PowerShell process
    execution. Deliberately narrow: it does not fire on the word
    "powershell" alone, nor on unrelated flags that merely start with
    "-enc" (e.g. "-Encoding").
    """

    rule_id = "encoded_powershell_command"
    name = "Encoded PowerShell Command"
    description = (
        "Detects PowerShell process executions using the -EncodedCommand "
        "(or -enc) flag to pass a base64-encoded command, a common "
        "technique for hiding payload content from casual log review."
    )
    severity = DetectionSeverity.HIGH
    confidence = DetectionConfidence.HIGH

    def evaluate(self, events: Sequence[SecurityEvent]) -> list[DetectionResult]:
        results: list[DetectionResult] = []
        for event in events:
            if self._matches(event):
                results.append(self._build_detection(event))
        return results

    @staticmethod
    def _matches(event: SecurityEvent) -> bool:
        if (event.event_type or "").strip().lower() != PROCESS_CREATION_EVENT_TYPE:
            return False
        if not is_powershell_process(event.process_name):
            return False
        command_line = truncate_for_scanning(event.command_line)
        if not command_line:
            return False
        return bool(_ENCODED_COMMAND_PATTERN.search(command_line))

    def _build_detection(self, event: SecurityEvent) -> DetectionResult:
        evidence = {
            "process_name": event.process_name,
            "command_line": event.command_line,
            "hostname": event.hostname,
            "username": event.username,
        }
        return self._build_result(
            title=f"Encoded PowerShell command on {event.hostname or 'unknown host'}",
            description=(
                "PowerShell was executed with an encoded (-EncodedCommand/-enc) "
                "argument, which can hide the actual command from casual review."
            ),
            evidence=evidence,
            related_event_ids=[event.id],
        )
