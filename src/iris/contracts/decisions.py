"""Engine output contract: decision records D1-D7 (IRIS Input Agreement v2.0, section 14).

Every decision carries status, confidence, the visible event IDs it relies on and the
versions that produced it. The evaluator scores these against the hidden reference key.
"""

from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from iris.contracts.common import (
    AttackTechniqueId,
    Confidence,
    ControlId,
    EpisodeId,
    NonEmptyStr,
    RiskId,
    ScenarioId,
    StrictModel,
    UtcDateTime,
)

PriorityLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class SubjectRef(StrictModel):
    kind: Literal["session", "incident", "asset", "risk", "control", "exception", "record", "scenario"]
    id: NonEmptyStr


class D1Payload(StrictModel):
    type: Literal["D1"] = "D1"
    verdict: Literal["malicious", "benign", "unknown"]
    scenario_class: str | None = None
    tactics: list[NonEmptyStr] = Field(default_factory=list)
    techniques: list[AttackTechniqueId] = Field(default_factory=list)


class D2Payload(StrictModel):
    type: Literal["D2"] = "D2"
    priority: PriorityLevel


class D3Payload(StrictModel):
    type: Literal["D3"] = "D3"
    risk_id: RiskId
    direction: Literal["up", "down", "none"]
    magnitude: float = Field(ge=0)  # in the organisation's own scale units


class ControlRecommendation(StrictModel):
    control_id: ControlId
    action: Literal["implement", "strengthen", "verify", "extend_scope", "remove", "relax"]
    rationale: NonEmptyStr
    d3fend_refs: list[str] = Field(default_factory=list)


class D4Payload(StrictModel):
    type: Literal["D4"] = "D4"
    recommendations: list[ControlRecommendation] = Field(min_length=1, max_length=3)


class D5Payload(StrictModel):
    type: Literal["D5"] = "D5"
    actions: list[
        Literal[
            "open_incident",
            "escalate",
            "notify_owner",
            "review_control",
            "review_exception",
            "update_register",
            "accept_risk",
            "close_incident",
            "monitor",
        ]
    ] = Field(min_length=1)


class D6Payload(StrictModel):
    type: Literal["D6"] = "D6"
    record_ref: NonEmptyStr
    flaw_type: NonEmptyStr
    explanation: NonEmptyStr
    proposed_change: dict[str, str] | None = None


class D7Payload(StrictModel):
    type: Literal["D7"] = "D7"
    estimates: dict[str, float] = Field(min_length=1)  # metric_id -> value (Part 7 metric ids)


Payload = Annotated[
    D1Payload | D2Payload | D3Payload | D4Payload | D5Payload | D6Payload | D7Payload,
    Field(discriminator="type"),
]


class DecisionRecord(StrictModel):
    decision_id: str = Field(pattern=r"^dec-[0-9A-Za-z_-]{1,64}$")
    scenario_id: ScenarioId
    episode_id: EpisodeId | None = None
    as_of: UtcDateTime
    type: Literal["D1", "D2", "D3", "D4", "D5", "D6", "D7"]
    subject_ref: SubjectRef
    payload: Payload | None = None
    status: Literal["ASSESSED", "ABSTAINED", "FAILED"]
    confidence: Confidence | None = None
    rationale: str | None = None
    evidence_event_ids: list[str] = Field(default_factory=list)
    context_refs: list[str] = Field(default_factory=list)
    engine_version: NonEmptyStr
    model_version: NonEmptyStr
    policy_version: NonEmptyStr

    @model_validator(mode="after")
    def _status_rules(self) -> Self:
        if self.status == "ASSESSED":
            if self.payload is None:
                raise ValueError("an ASSESSED decision needs a payload")
            if self.payload.type != self.type:
                raise ValueError(f"payload type {self.payload.type} does not match decision type {self.type}")
            if self.confidence is None:
                raise ValueError("an ASSESSED decision needs a confidence")
        elif self.payload is not None and self.payload.type != self.type:
            raise ValueError("payload type does not match decision type")
        if (
            self.type != "D7"
            and self.status == "ASSESSED"
            and not (self.evidence_event_ids or self.context_refs)
        ):
            raise ValueError("an ASSESSED decision must cite visible evidence (event ids or context refs)")
        return self
