"""Review orchestration: one focused pass per vulnerability family.

Why: in T05 run 2 a single open-ended pass stopped after its first finding and never
looked at authorization or file access. Research reports that prompts scoped to one
bug class beat open-ended ones (arXiv 2606.21397). Each pass gets the family's
review questions from its knowledge card, its own hypothesis state and budget share,
and shares the tool registry (one trace, unique event ids, shared evidence).
`single_pass=True` keeps the open-ended mode as an ablation.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from .agent import Agent, RunResult
from .config import Config
from .model import ModelAdapter
from .schemas import FinalDecision
from .tools import ToolRegistry

ROOT = Path(__file__).resolve().parent.parent
CARDS = ROOT / "data" / "knowledge_cards"
PREFIX = {"sql_injection": "SQLI", "path_traversal": "PATH", "authorization_idor": "AUTHZ",
          "os_command_injection": "CMDI", "xss": "XSS"}

OPEN_TASK = ("Review this Flask application for {families}. Map the routes and their authorization first, "
             "then investigate and report only findings supported by evidence you have read.")

FAMILY_TASK = (
    "Review this Flask application for ONE vulnerability family only: {title} ({cwe}).\n"
    "Work like this: locate candidate code with search_code (e.g. {hints}) or scan_static, read the relevant "
    "functions AND their callers/decorators, then decide. Check every route, not just the first hit. "
    "Report each distinct root cause; a pattern that is safe (bound parameters, allow-list, ownership filter, "
    "safe helper) must be rejected, not reported.\n"
    "Questions to answer:\n{questions}"
)
# knowledge ablation: same task without the card's review questions
NO_CARDS_QUESTIONS = "- Is there a real vulnerability of this family? Cite the code you read."

SEARCH_HINTS = {
    "sql_injection": '"execute(", "text(", "SELECT"',
    "path_traversal": '"send_file", "open(", "os.path.join"',
    "authorization_idor": '"@app.", "login_required", "current_user", "owner"',
    "os_command_injection": '"subprocess", "os.system", "shell=True"',
    "xss": '"Markup", "|safe", "render_template_string", "<"',
}


@dataclass
class ReviewResult:
    final: FinalDecision
    passes: dict[str, RunResult]


def family_task(family: str, use_cards: bool = True) -> str:
    card = yaml.safe_load((CARDS / f"{family}.yaml").read_text(encoding="utf-8"))
    questions = "\n".join(f"- {q}" for q in card["review_questions"]) if use_cards else NO_CARDS_QUESTIONS
    return FAMILY_TASK.format(title=card["title"], cwe=card["cwe"]["primary"],
                              hints=SEARCH_HINTS.get(family, '"request."'), questions=questions)


def _rename(final: FinalDecision, prefix: str) -> dict:
    d = final.model_dump(by_alias=True)

    def r(x):
        return f"{prefix}-{x}" if x else x
    for f in d["findings"]:
        f["id"] = r(f["id"])
        f["hypothesis_ids"] = [r(h) for h in f["hypothesis_ids"]]
    for h in d["coverage"]["hypotheses"]:
        h["id"], h["finding_id"] = r(h["id"]), r(h["finding_id"])
    for u in d["hypothesis_updates"]:
        u["id"] = r(u["id"])
    return d


def merge(finals: dict[str, FinalDecision]) -> FinalDecision:
    statuses = {f.status for f in finals.values()}
    status = "complete" if statuses == {"complete"} else ("blocked" if statuses == {"blocked"} else "partial")
    merged = {"kind": "final", "status": status, "findings": [], "limitations": [], "hypothesis_updates": [],
              "coverage": {"reviewed_paths": [], "reviewed_entrypoints": [], "checks": [], "hypotheses": [],
                           "omitted_areas": []}}
    seen = set()
    for family, final in finals.items():
        d = _rename(final, PREFIX.get(family, family.upper()))
        for f in d["findings"]:
            ev = f["evidence"][0]
            key = (f["cwe_id"], ev["file"], ev["line_start"])
            if key in seen:
                merged["limitations"].append(f"{f['id']}: duplicate of an earlier finding at {ev['file']}:{ev['line_start']}")
                continue
            seen.add(key)
            merged["findings"].append(f)
        merged["limitations"] += [f"[{family}] {x}" for x in d["limitations"]]
        merged["hypothesis_updates"] += d["hypothesis_updates"]
        for k in ("reviewed_paths", "reviewed_entrypoints", "checks", "omitted_areas"):
            merged["coverage"][k] = sorted(set(merged["coverage"][k]) | set(d["coverage"][k]))
        merged["coverage"]["hypotheses"] += d["coverage"]["hypotheses"]
    return FinalDecision.model_validate(merged)


def run_review(config: Config, model: ModelAdapter, registry: ToolRegistry, run_dir: Path | None = None,
               single_pass: bool = False, verify: bool = True, use_cards: bool = True) -> ReviewResult:
    if single_pass:
        agent = Agent(config, model, registry, verify=verify)
        res = agent.run(OPEN_TASK.format(families=", ".join(config.enabled_families)), run_dir)
        return ReviewResult(final=res.final, passes={"open": res})

    n = len(config.enabled_families)
    share = config.model_copy(update={
        "max_model_calls": max(3, config.max_model_calls // n),
        "max_tool_calls": max(2, config.max_tool_calls // n),
        "max_seconds": max(60, config.max_seconds // n),
    })
    passes: dict[str, RunResult] = {}
    for family in config.enabled_families:
        registry.trace.record({"type": "pass_start", "family": family})
        agent = Agent(share, model, registry, verify=verify)
        passes[family] = agent.run(family_task(family, use_cards), run_dir / family if run_dir else None)
    final = merge({f: r.final for f, r in passes.items()})
    if run_dir is not None:
        (run_dir / "final.json").write_text(final.model_dump_json(indent=2, by_alias=True), encoding="utf-8")
    return ReviewResult(final=final, passes=passes)
