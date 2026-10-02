"""Human-readable Markdown report from a validated final decision.

Everything the model wrote (titles, rationales, remediation) and every code
excerpt is treated as untrusted text: Markdown links/images are neutralised so a
rendered report cannot fetch a remote URL (the CamoLeak exfiltration channel),
and excerpts go into code fences longer than any backtick run inside them.
"""

from __future__ import annotations

import re

from .schemas import FinalDecision, Finding

SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational", "undetermined"]


def safe_text(s: str | None) -> str:
    if not s:
        return ""
    s = s.replace("\r", " ")
    s = re.sub(r"!\[", r"!\\[", s)                               # images
    s = re.sub(r"\]\(", r"\\](", s)                              # inline links
    s = re.sub(r"<(https?://[^>]+)>", r"\1", s)                  # autolinks
    s = re.sub(r"(?i)\b(https?)://", r"\1[:]//", s)              # bare URLs: not clickable, not fetched
    s = s.replace("<", "&lt;").replace(">", "&gt;")              # raw HTML
    s = s.replace("|", "\\|").replace("\n", " ")                 # keep table cells intact
    return s


def code_block(code: str, lang: str = "python") -> str:
    longest = max((len(m) for m in re.findall(r"`+", code)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}{lang}\n{code}\n{fence}"


def _finding_md(f: Finding) -> str:
    out = [f"### {safe_text(f.id)} — {safe_text(f.title)}",
           "",
           f"| | |\n|---|---|\n| CWE | {safe_text(f.cwe_id) or 'n/a'} |\n| Severity | {f.severity} — {safe_text(f.severity_rationale)} |\n"
           f"| Confidence | {f.confidence} — {safe_text(f.confidence_rationale)} |\n"
           f"| Analysis / verification | {f.analysis_status} / {f.verification_status} |\n"
           f"| Entry point | {safe_text(f.entrypoint)} |\n| Source → sink | {safe_text(f.source_to_sink)} |\n"
           f"| Trust boundary | {safe_text(f.trust_boundary)} |",
           ""]
    out.append("**Evidence**")
    for e in f.evidence:
        out += ["", f"`{safe_text(e.file)}:{e.line_start}-{e.line_end}` (event {safe_text(e.tool_event_id)}) — "
                    f"{safe_text(e.supports)}", "", code_block(e.excerpt)]
    if f.counterevidence:
        out += ["", "**Counter-evidence considered**"]
        for e in f.counterevidence:
            out += ["", f"`{safe_text(e.file)}:{e.line_start}-{e.line_end}` — {safe_text(e.supports)}", "",
                    code_block(e.excerpt)]
    if f.controls:
        out += ["", "**Controls observed:** " + "; ".join(safe_text(c) for c in f.controls)]
    if f.preconditions:
        out += ["", "**Preconditions:** " + "; ".join(safe_text(c) for c in f.preconditions)]
    out += ["", f"**Impact:** {safe_text(f.impact)}", "", f"**Remediation:** {safe_text(f.remediation)}"]
    if f.regression_tests:
        out += ["", "**Regression tests:**"] + [f"- {safe_text(t)}" for t in f.regression_tests]
    if f.sources:
        out += ["", "**Knowledge sources:** " + "; ".join(
            f"{safe_text(s.id)} ({safe_text(s.title)}{', ' + safe_text(s.version) if s.version else ''})" for s in f.sources)]
    if f.unknowns:
        out += ["", "**Unknowns:** " + "; ".join(safe_text(u) for u in f.unknowns)]
    return "\n".join(out)


def render(final: FinalDecision, target: str, run_meta: dict | None = None,
           controller_notes: list[str] | None = None) -> str:
    findings = sorted(final.findings, key=lambda f: SEVERITY_ORDER.index(f.severity))
    lines = [f"# Security review — {safe_text(target)}", "",
             f"Status: **{final.status}** · findings: **{len(findings)}** · "
             "verification: static evidence only unless a finding says otherwise", ""]
    if run_meta:
        lines += ["| Run | |", "|---|---|"] + [f"| {safe_text(str(k))} | {safe_text(str(v))} |" for k, v in run_meta.items()] + [""]
    lines += ["> Findings are evidence-backed candidates, not proof of exploitability. An empty report does not "
              "mean the code is secure.", ""]
    lines += ["## Findings", ""]
    if not findings:
        lines += ["None reported.", ""]
    for f in findings:
        lines += [_finding_md(f), ""]
    hyps = final.coverage.hypotheses
    if hyps:
        lines += ["## Hypotheses examined", "", "| Id | Status | Question | Reason |", "|---|---|---|---|"]
        lines += [f"| {safe_text(h.id)} | {h.analysis_status} | {safe_text(h.question)} | {safe_text(h.reason)} |"
                  for h in hyps] + [""]
    cov = final.coverage
    lines += ["## Coverage", "",
              f"- Reviewed paths: {', '.join(safe_text(p) for p in cov.reviewed_paths) or 'none'}",
              f"- Entry points: {', '.join(safe_text(p) for p in cov.reviewed_entrypoints) or 'none'}",
              f"- Omitted: {', '.join(safe_text(p) for p in cov.omitted_areas) or 'none listed'}", ""]
    if final.limitations or controller_notes:
        lines += ["## Limitations and controller notes", ""]
        lines += [f"- {safe_text(x)}" for x in final.limitations]
        lines += [f"- controller: {safe_text(x)}" for x in (controller_notes or [])]
    return "\n".join(lines).rstrip() + "\n"
