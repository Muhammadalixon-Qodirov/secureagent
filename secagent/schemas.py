"""Wire contract between the controller and the model.

Mirrors section 7 of SECURITY_AGENT_SYSTEM_PROMPT.md exactly: every model turn is
one `ActionDecision` or one `FinalDecision`. Unknown keys are rejected, so the
model cannot smuggle extra fields (e.g. policy overrides) through the contract.

Structural validation only. Semantic checks that need run state (do cited
tool events exist, do excerpts match the lines that were read, is a
`reproduced` status backed by a lab event) belong to the controller.
"""

from __future__ import annotations

from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, model_validator

AnalysisStatus = Literal["candidate", "rejected", "inconclusive"]
VerificationStatus = Literal["not_run", "reproduced", "not_reproduced", "error"]
Severity = Literal["critical", "high", "medium", "low", "informational", "undetermined"]
Confidence = Literal["high", "medium", "low"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class _LineRange(_Strict):
    file: str = Field(min_length=1)
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)

    @model_validator(mode="after")
    def _ordered(self):
        if self.line_end < self.line_start:
            raise ValueError("line_end must be >= line_start")
        return self


class EvidenceRef(_LineRange):
    tool_event_id: str = Field(min_length=1)


class Evidence(_LineRange):
    excerpt: str
    tool_event_id: str = Field(min_length=1)
    supports: str


class TraceEdge(_Strict):
    from_: EvidenceRef = Field(alias="from")
    to: EvidenceRef
    relation: str
    status: Literal["observed", "inferred", "unresolved"]


class HypothesisUpdate(_Strict):
    """Only `id` is required; omitted fields leave controller state unchanged,
    supplied lists replace that field's state."""

    id: str = Field(min_length=1)
    claim: str | None = None
    family: str | None = None
    entrypoint: str | None = None
    source: str | None = None
    sink_or_protected_operation: str | None = None
    trace_edges: list[TraceEdge] | None = None
    observed_controls: list[str] | None = None
    preconditions: list[str] | None = None
    missing_context: list[str] | None = None
    supporting_evidence: list[EvidenceRef] | None = None
    contradicting_evidence: list[EvidenceRef] | None = None
    next_check: str | None = None
    analysis_status: AnalysisStatus | None = None


class Source(_Strict):
    id: str
    title: str
    url: str | None
    version: str | None


class Verification(_Strict):
    method: str | None
    event_ids: list[str]
    observations: list[str]
    limits: list[str]


class Finding(_Strict):
    id: str
    hypothesis_ids: list[str] = Field(min_length=1)
    title: str
    cwe_id: str | None = Field(pattern=r"^CWE-\d+$")
    analysis_status: Literal["candidate"]
    verification_status: VerificationStatus
    severity: Severity
    severity_rationale: str
    confidence: Confidence
    confidence_rationale: str
    entrypoint: str
    source_to_sink: str
    trust_boundary: str
    controls: list[str]
    preconditions: list[str]
    impact: str
    evidence: list[Evidence] = Field(min_length=1)
    counterevidence: list[Evidence]
    sources: list[Source]
    verification: Verification
    remediation: str
    regression_tests: list[str]
    unknowns: list[str]

    @model_validator(mode="after")
    def _verification_consistent(self):
        # A runtime status is a claim and needs a lab event. (not_run with stray event ids or
        # observations is not a false claim; the controller clears those fields - rejecting the
        # whole decision here lost a correct finding four times in T05 run 5.)
        if self.verification_status != "not_run" and not self.verification.event_ids:
            raise ValueError(f"verification_status {self.verification_status} requires lab event_ids")
        return self


class HypothesisSummary(_Strict):
    id: str
    question: str
    analysis_status: AnalysisStatus
    verification_status: VerificationStatus
    reason: str
    finding_id: str | None


class Coverage(_Strict):
    reviewed_paths: list[str]
    reviewed_entrypoints: list[str]
    checks: list[str]
    hypotheses: list[HypothesisSummary]
    omitted_areas: list[str]


class ActionDecision(_Strict):
    kind: Literal["action"]
    tool: str = Field(min_length=1)
    arguments: dict
    hypothesis_id: str | None
    hypothesis_update: HypothesisUpdate | None
    purpose: str = Field(min_length=1)

    @model_validator(mode="after")
    def _update_matches_hypothesis(self):
        if self.hypothesis_id is None and self.hypothesis_update is not None:
            raise ValueError("inventory actions (hypothesis_id null) require hypothesis_update null")
        if self.hypothesis_update is not None and self.hypothesis_update.id != self.hypothesis_id:
            raise ValueError("hypothesis_update.id must equal hypothesis_id")
        return self


class FinalDecision(_Strict):
    kind: Literal["final"]
    status: Literal["complete", "partial", "blocked"]
    findings: list[Finding]
    coverage: Coverage
    limitations: list[str]
    hypothesis_updates: list[HypothesisUpdate]


Decision = Annotated[Union[ActionDecision, FinalDecision], Field(discriminator="kind")]
DecisionAdapter: TypeAdapter[ActionDecision | FinalDecision] = TypeAdapter(Decision)


def parse_decision(raw: str) -> ActionDecision | FinalDecision:
    """Validate one model turn. Raises pydantic.ValidationError on any deviation."""
    return DecisionAdapter.validate_json(raw)
