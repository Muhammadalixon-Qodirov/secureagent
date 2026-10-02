"""Check that evidence the model cites was actually observed in this run.

A reference `{file, line_start, line_end, tool_event_id}` is valid only if that
event exists, succeeded, and its result covers that file and those lines:
  read_file   — the lines were inside the window that was read
  search_code — a match on that file within the range
  scan_static — a finding on that file overlapping the range
Excerpts are checked against the text that was actually read.
"""

from __future__ import annotations

import re

from .schemas import Evidence, EvidenceRef
from .tools import ToolResult

EVIDENCE_TOOLS = {"read_file", "search_code", "scan_static"}


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def check_ref(ref: EvidenceRef | Evidence, results: dict[str, ToolResult]) -> str | None:
    """Return None if the reference is backed by an observation, else the reason it is not."""
    ev = results.get(ref.tool_event_id)
    if ev is None:
        return f"{ref.tool_event_id}: no such tool event"
    if ev.status != "ok" or not ev.data:
        return f"{ref.tool_event_id}: event did not succeed ({ev.status})"
    if ev.tool not in EVIDENCE_TOOLS:
        return f"{ref.tool_event_id}: {ev.tool} results are not code evidence"
    f, a, b = ref.file.replace("\\", "/"), ref.line_start, ref.line_end
    d = ev.data
    if ev.tool == "read_file":
        if d["path"] != f:
            return f"{ref.tool_event_id}: read {d['path']}, not {f}"
        if a < d["start_line"] or b > d["end_line"]:
            return f"{ref.tool_event_id}: lines {a}-{b} outside the window read ({d['start_line']}-{d['end_line']})"
        return None
    if ev.tool == "search_code":
        if any(m["path"] == f and a <= m["line"] <= b for m in d["matches"]):
            return None
        return f"{ref.tool_event_id}: no search match in {f}:{a}-{b}"
    if any(x["file"] == f and x["line_start"] <= b and x["line_end"] >= a for x in d["findings"]):
        return None
    return f"{ref.tool_event_id}: no scanner finding in {f}:{a}-{b}"


def observed_text(ref: Evidence, results: dict[str, ToolResult]) -> str | None:
    """Text of the cited lines as observed (read_file windows and search matches)."""
    ev = results.get(ref.tool_event_id)
    if ev is None or not ev.data:
        return None
    if ev.tool == "read_file":
        return "\n".join(x["text"] for x in ev.data["lines"] if ref.line_start <= x["n"] <= ref.line_end)
    if ev.tool == "search_code":
        return "\n".join(m["text"] for m in ev.data["matches"]
                         if m["path"] == ref.file and ref.line_start <= m["line"] <= ref.line_end)
    return None


def excerpt_matches(ref: Evidence, results: dict[str, ToolResult]) -> bool | None:
    """True/False if the excerpt can be checked against observed text, None if not checkable
    (e.g. scanner findings carry no source text). Every non-empty excerpt line must occur in
    the observed lines (whitespace-normalised); "…" marks an elision."""
    text = observed_text(ref, results)
    if text is None:
        return None
    hay = _norm(text)
    parts = [_norm(p) for line in ref.excerpt.splitlines() for p in re.split(r"…|\.\.\.", line)]
    parts = [p for p in parts if p]
    return bool(parts) and all(p in hay for p in parts)
