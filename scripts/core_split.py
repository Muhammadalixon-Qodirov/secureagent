"""Secondary metric: IDOR-family true positives split by the entry's PRIMARY CWE.

The declared matching rule is family-level (primary or any acceptable CWE). On
the FastAPI set that counted location matches on mass-assignment / CORS /
business-logic entries as IDOR true positives (docs/experiments.md, T11
erratum). This script reports, per system, how many IDOR-family true positives
fall on entries whose primary CWE is access control proper ("core") and how
many on the rest, plus precision/recall restricted to core entries (findings
that match a non-core entry are ignored there, neither TP nor FP).

    python scripts/core_split.py [realvuln|realvuln_fastapi|realvuln_django]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from secagent.evaluate import DATASETS, wilson  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
CORE = {"CWE-639", "CWE-862", "CWE-863", "CWE-284", "CWE-285", "CWE-306", "CWE-425", "CWE-566"}
GT = {"realvuln": "eval/realvuln", "realvuln_fastapi": "eval/realvuln_fastapi", "realvuln_django": "eval/realvuln_django"}


def main() -> int:
    ds = sys.argv[1] if len(sys.argv) > 1 else "realvuln_fastapi"
    loader, _, runs = DATASETS[ds]
    cases, _ = loader()
    prim = {}
    for p in (ROOT / GT[ds] / "ground_truth").glob("*.json"):
        g = json.loads(p.read_text(encoding="utf-8"))
        for f in g["findings"]:
            prim[(g["repo_id"], f["id"])] = f["primary_cwe"]
    idor = [c for c in cases if c.family == "authorization_idor" and c.vulnerable]
    core_ids = {(c.app, c.id) for c in idor if prim[(c.app, c.id)] in CORE}
    print(f"# {ds}: IDOR-family vulnerable entries {len(idor)}, core access-control primary CWE {len(core_ids)}\n")
    print("| System | IDOR TP core | IDOR TP other | IDOR FP | Core recall (95% CI) | Core precision |")
    print("|---|---|---|---|---|---|")
    for sp in sorted(runs.glob("*/scores.json")):
        d = json.loads(sp.read_text(encoding="utf-8"))
        core = other = 0
        for app, a in d["per_app"].items():
            for tid in a["tp"]:
                if (app, tid) in core_ids:
                    core += 1
                elif any(c.app == app and c.id == tid and c.family == "authorization_idor" for c in cases):
                    other += 1
        m = d["metrics"]["authorization_idor"]
        fp = m["fp_lookalike"] + m["fp_unmatched"]
        ci = wilson(core, len(core_ids))
        prec = f"{core / (core + fp):.2f}" if core + fp else "n/a"
        print(f"| {sp.parent.name} | {core} | {other} | {fp} | {core / max(1, len(core_ids)):.2f} "
              f"({ci[0]:.2f}–{ci[1]:.2f}) | {prec} |" if ci else f"| {sp.parent.name} | {core} | {other} | {fp} | n/a | {prec} |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
