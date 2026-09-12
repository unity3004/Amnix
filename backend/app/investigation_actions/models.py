"""Internal representation of one application-controlled, investigation-
only recommendable action. Purely a typed, in-code data model — no
database table, no migration. See app.investigation_actions.registry for
the actual catalog and the only supported lookup function.
"""

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

_ACTION_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_]{1,63}$")


class InvestigationAction(BaseModel):
    """One catalog entry: a safe, investigation-only action AMNIX may
    offer as a candidate for the Copilot to recommend.

    `applicable_rule_ids` and `required_entities` are the ONLY inputs to
    candidate selection (see app.investigation_actions.registry.
    get_candidate_actions) — deliberately just two plain string sets, not
    a rules DSL. `required_entities` names zero or more field names on
    app.schemas.investigation.InvestigationEntities (e.g. "usernames",
    "source_ips") that must be non-empty for this action to be offered;
    an empty set means "no entity requirement beyond the rule matching".

    This model is never sent to a provider directly — see
    app.schemas.ai.AIActionCandidate for the smaller, AI-facing shape
    AIContextBuilder maps this into (drops applicable_rule_ids/
    required_entities entirely, since those are AMNIX's own selection
    machinery, not something a model needs to reason about).
    """

    model_config = ConfigDict(frozen=True)

    action_id: str = Field(min_length=2, max_length=64)
    label: str = Field(min_length=1, max_length=150)
    description: str = Field(min_length=1, max_length=500)
    applicable_rule_ids: frozenset[str]
    required_entities: frozenset[str] = frozenset()

    @field_validator("action_id")
    @classmethod
    def _well_formed_action_id(cls, v: str) -> str:
        if not _ACTION_ID_PATTERN.match(v):
            raise ValueError(
                f"'{v}' is not a well-formed action_id (expected lowercase snake_case, e.g. 'review_host_activity')"
            )
        return v
