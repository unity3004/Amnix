"""Internal representation of one (detection rule -> ATT&CK technique)
mapping entry. Purely a typed, in-code data model — no database table,
no migration. See app.mitre.registry for the actual mapping data and the
only supported lookup function.
"""

from pydantic import BaseModel, ConfigDict, Field


class MitreTechnique(BaseModel):
    """One application-controlled candidate mapping from an AMNIX
    detection rule to a MITRE ATT&CK (sub-)technique.

    `source_rule_id` makes this a mapping-table row, not a deduplicated
    technique catalog entry: the same technique_id can legitimately
    appear in multiple MitreTechnique instances if more than one rule
    maps to it (e.g. T1059.001 for both suspicious_powershell_execution
    and encoded_powershell_command) — each instance still carries the
    rule it came from, so provenance is never lost.
    """

    model_config = ConfigDict(frozen=True)

    technique_id: str = Field(min_length=1, max_length=20)
    name: str = Field(min_length=1, max_length=200)
    tactic: str = Field(min_length=1, max_length=100)
    description: str = Field(min_length=1, max_length=2000)
    source_rule_id: str = Field(min_length=1, max_length=100)
