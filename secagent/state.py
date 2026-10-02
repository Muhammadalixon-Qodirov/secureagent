"""Hypothesis state, owned by the controller.

The model changes it only through `hypothesis_update(s)`: omitted fields stay as
they are, supplied lists replace that field. An update is rejected as a whole if it
cites evidence that was not observed, so state never contains invented evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .evidence import check_ref
from .schemas import HypothesisUpdate
from .tools import ToolResult

MAX_HYPOTHESES = 30
MAX_LIST_ITEMS = 12

_LIST_FIELDS = ("trace_edges", "observed_controls", "preconditions", "missing_context",
                "supporting_evidence", "contradicting_evidence")


@dataclass
class Hypothesis:
    id: str
    claim: str | None = None
    family: str | None = None
    entrypoint: str | None = None
    source: str | None = None
    sink_or_protected_operation: str | None = None
    trace_edges: list = field(default_factory=list)
    observed_controls: list = field(default_factory=list)
    preconditions: list = field(default_factory=list)
    missing_context: list = field(default_factory=list)
    supporting_evidence: list = field(default_factory=list)
    contradicting_evidence: list = field(default_factory=list)
    next_check: str | None = None
    analysis_status: str = "inconclusive"


class HypothesisStore:
    def __init__(self) -> None:
        self.items: dict[str, Hypothesis] = {}

    def apply(self, update: HypothesisUpdate, results: dict[str, ToolResult]) -> list[str]:
        """Apply one update. Returns rejection reasons (empty list = applied)."""
        if update.id not in self.items and len(self.items) >= MAX_HYPOTHESES:
            return [f"{update.id}: hypothesis limit ({MAX_HYPOTHESES}) reached"]
        errors = []
        refs = list(update.supporting_evidence or []) + list(update.contradicting_evidence or [])
        for edge in update.trace_edges or []:
            refs += [edge.from_, edge.to]
        for r in refs:
            reason = check_ref(r, results)
            if reason:
                errors.append(f"{update.id}: {reason}")
        for name in _LIST_FIELDS:
            value = getattr(update, name)
            if value is not None and len(value) > MAX_LIST_ITEMS:
                errors.append(f"{update.id}: {name} has more than {MAX_LIST_ITEMS} items")
        if errors:
            return errors
        h = self.items.setdefault(update.id, Hypothesis(id=update.id))
        for name, value in update.model_dump(exclude_unset=True, by_alias=False).items():
            if name == "id" or (name == "analysis_status" and value is None):
                continue
            if name in _LIST_FIELDS and value is None:
                value = []                      # explicit null on a list clears it
            setattr(h, name, value)
        return []

    def render(self) -> str:
        """Compact, controller-written view of the state for the next model turn."""
        if not self.items:
            return "(no hypotheses yet)"
        lines = []
        for h in self.items.values():
            ev = ", ".join(f"{e['file']}:{e['line_start']}-{e['line_end']}@{e['tool_event_id']}"
                           for e in h.supporting_evidence) or "none"
            con = ", ".join(f"{e['file']}:{e['line_start']}-{e['line_end']}@{e['tool_event_id']}"
                            for e in h.contradicting_evidence) or "none"
            lines.append(
                f"{h.id} [{h.analysis_status}] family={h.family} claim={h.claim!r}\n"
                f"   entrypoint={h.entrypoint} source={h.source} sink={h.sink_or_protected_operation}\n"
                f"   controls={h.observed_controls} missing={h.missing_context} next_check={h.next_check!r}\n"
                f"   supporting={ev} contradicting={con}")
        return "\n".join(lines)
