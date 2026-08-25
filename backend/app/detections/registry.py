"""Registry of detection rules available to the DetectionEngine."""

from app.detections.base import DetectionRule
from app.detections.rules.brute_force import BruteForceDetectionRule
from app.detections.rules.encoded_powershell import EncodedPowerShellDetectionRule
from app.detections.rules.suspicious_powershell import SuspiciousPowerShellDetectionRule


class DetectionRuleRegistry:
    """Holds a set of DetectionRule instances by rule_id.

    Adding a new rule to the system means constructing it and calling
    `register()` — nothing here or in the DetectionEngine needs to
    change.
    """

    def __init__(self) -> None:
        self._rules: dict[str, DetectionRule] = {}

    def register(self, rule: DetectionRule) -> None:
        if rule.rule_id in self._rules:
            raise ValueError(f"Detection rule '{rule.rule_id}' is already registered")
        self._rules[rule.rule_id] = rule

    def unregister(self, rule_id: str) -> None:
        self._rules.pop(rule_id, None)

    @property
    def rules(self) -> list[DetectionRule]:
        return list(self._rules.values())

    def __len__(self) -> int:
        return len(self._rules)


def build_default_registry() -> DetectionRuleRegistry:
    """Build a registry pre-populated with AMNIX's built-in detection rules."""
    registry = DetectionRuleRegistry()
    registry.register(BruteForceDetectionRule())
    registry.register(SuspiciousPowerShellDetectionRule())
    registry.register(EncodedPowerShellDetectionRule())
    return registry
