"""Copy evaluation results from runs/eval (local, not committed) to eval/results (committed).

Exports per-system scores and per-app findings, and writes a Markdown results
table (eval/results/RESULTS.md). Raw model replies and traces stay in runs/.

    python scripts/export_results.py [holdout|realvuln|realvuln_fastapi|realvuln_django]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATASETS = {
    "holdout": (ROOT / "runs" / "eval", ROOT / "eval" / "results",
                "48 cases (22 vulnerable, 26 safe look-alikes), 10 synthetic apps", "docs/evaluation_protocol.md"),
    "realvuln": (ROOT / "runs" / "eval_realvuln", ROOT / "eval" / "results_realvuln",
                 "130 entries (90 vulnerable, 40 traps), 15 RealVuln Flask apps", "docs/realvuln_protocol.md"),
    "realvuln_fastapi": (ROOT / "runs" / "eval_fastapi", ROOT / "eval" / "results_fastapi",
                         "244 entries (182 vulnerable, 62 traps), RealVuln FastAPI apps", "docs/fastapi_protocol.md"),
    "realvuln_django": (ROOT / "runs" / "eval_django", ROOT / "eval" / "results_django",
                        "277 entries (204 vulnerable, 73 traps), 23 RealVuln Django apps", "docs/django_protocol.md"),
}

ORDER = ["semgrep", "single_shot", "agent", "agent_no_verify", "agent_no_cards", "agent_single_pass",
         "agent_no_verify_no_cards", "agent_v1", "agent_v2", "agent_v2_no_verify",
         "authz_only", "agent_v3", "agent_v3_no_verify", "agent_v3_hardened",
         "authz_v4_only", "agent_v4"]
LABEL = {
    "semgrep": "Semgrep only (project rules)",
    "single_shot": "Single-shot LLM (no tools)",
    "agent": "Agent (per-family + cards + verifier)",
    "agent_no_verify": "Agent without verifier",
    "agent_no_cards": "Agent without card questions",
    "agent_single_pass": "Agent, one open-ended pass",
    "agent_no_verify_no_cards": "Agent without verifier and cards (post-hoc)",
    "agent_v1": "Agent v1 (no verifier; best v1 on holdout)",
    "agent_v2": "Agent v2 (sweep + verifier v2)",
    "agent_v2_no_verify": "Agent v2 without verifier",
    "authz_only": "Authorization analysis only (no model)",
    "agent_v3": "Agent v3 (v2 + authorization seeds)",
    "agent_v3_no_verify": "Agent v3 without verifier",
    "agent_v3_hardened": "Agent v3 + injection hardening (v3.1)",
    "authz_v4_only": "v4 authorization analysis only (no model)",
    "agent_v4": "Agent v4 (helper resolution + Django)",
}


def fmt(v, ci=None):
    if v is None:
        return "n/a"
    return f"{v:.2f}" + (f" ({ci[0]:.2f}–{ci[1]:.2f})" if ci else "")


def main() -> int:
    dataset = sys.argv[1] if len(sys.argv) > 1 else "holdout"
    SRC, DST, what, protocol = DATASETS[dataset]
    DST.mkdir(parents=True, exist_ok=True)
    rows, fam_rows = [], []
    for system in ORDER:
        f = SRC / system / "scores.json"
        if not f.exists():
            continue
        s = json.loads(f.read_text(encoding="utf-8"))
        per_app = {}
        for app, a in s["per_app"].items():
            res = SRC / system / app / "result.json"
            findings = json.loads(res.read_text(encoding="utf-8"))["norms"] if res.exists() else None
            per_app[app] = {k: a[k] for k in ("tp", "fn", "fp_safe", "fp_unmatched", "duplicates", "out_of_scope")}
            per_app[app]["findings"] = findings
            per_app[app]["seconds"] = a["run"].get("seconds")
        (DST / f"{system}.json").write_text(json.dumps({"system": system, "metrics": s["metrics"], "per_app": per_app},
                                                       indent=2, ensure_ascii=False), encoding="utf-8")
        m = s["metrics"]["micro"]
        secs = [v["seconds"] for v in per_app.values() if v["seconds"]]
        rows.append(f"| {LABEL[system]} | {m['tp']} | {m['fp_lookalike'] + m['fp_unmatched']} | {m['fn']} | "
                    f"{fmt(m['precision'], m['precision_ci95'])} | {fmt(m['recall'], m['recall_ci95'])} | "
                    f"{fmt(m['f1'])} | {fmt(m['lookalike_fp_rate'])} | "
                    f"{(sum(secs) / len(secs)):.0f} s |" if secs else
                    f"| {LABEL[system]} | {m['tp']} | {m['fp_lookalike'] + m['fp_unmatched']} | {m['fn']} | "
                    f"{fmt(m['precision'], m['precision_ci95'])} | {fmt(m['recall'], m['recall_ci95'])} | "
                    f"{fmt(m['f1'])} | {fmt(m['lookalike_fp_rate'])} | n/a |")
        fam_rows.append(f"| {LABEL[system]} | " + " | ".join(
            f"{s['metrics'][fam]['tp']}/{s['metrics'][fam]['tp'] + s['metrics'][fam]['fn']}"
            f" · FP {s['metrics'][fam]['fp_lookalike'] + s['metrics'][fam]['fp_unmatched']}"
            for fam in ("sql_injection", "path_traversal", "authorization_idor")) + " |")
    table = ("| System | TP | FP | FN | Precision (95% CI) | Recall (95% CI) | F1 | Look-alike FP rate | Time / app |\n"
             "|---|---|---|---|---|---|---|---|---|\n" + "\n".join(rows))
    fam = ("| System | SQLi found · FP | Path traversal found · FP | IDOR found · FP |\n|---|---|---|---|\n"
           + "\n".join(fam_rows))
    md = (f"# Results: {dataset}\n\n{what}, qwen3:8b, temperature 0.\n"
          f"Protocol: {protocol}. Generated by scripts/export_results.py {dataset}.\n\n{table}\n\n"
          f"Per family (found / vulnerable cases):\n\n{fam}\n")
    (DST / "RESULTS.md").write_text(md, encoding="utf-8")
    print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
