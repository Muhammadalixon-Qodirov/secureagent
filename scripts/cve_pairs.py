"""Paired metric for the CVE-replay set (docs/cve_replay_protocol.md).

For every advisory: detected = the system reported the advisory's family at the lines the fix
changed, on the vulnerable snapshot; silent = it did not report that family there on the fixed
snapshot; pair success = detected and silent. Also the number of other in-scope findings per
snapshot (unlabelled places - not called false positives, the code is real and may have other bugs).

    python scripts/cve_pairs.py [cve_dev|cve_test]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from secagent.evaluate import DATASETS, wilson  # noqa: E402

FAMILIES = ["sql_injection", "path_traversal", "authorization_idor"]


def main() -> int:
    ds = sys.argv[1] if len(sys.argv) > 1 else "cve_dev"
    loader, _, runs = DATASETS[ds]
    cases, _ = loader()
    fam = {c.id: c.family for c in cases if c.vulnerable}
    print(f"# {ds}: {len(fam)} advisories ("
          + ", ".join(f"{f} {sum(v == f for v in fam.values())}" for f in FAMILIES) + ")\n")
    print("| System | Detected (95% CI) | Still flagged after the fix | Pair success (95% CI) | "
          "SQLi / path / authz pairs | Other findings per snapshot |")
    print("|---|---|---|---|---|---|")
    for d in sorted(p for p in runs.iterdir() if (p / "scores.json").exists()):
        per = json.loads((d / "scores.json").read_text(encoding="utf-8"))["per_app"]
        if any(f"{i}/{label}" not in per for i in fam for label in ("vulnerable", "fixed")):
            print(f"| {d.name} | incomplete run | | | | |")
            continue
        det = {i for i in fam if i in per[f"{i}/vulnerable"]["tp"]}
        still = {i for i in fam if f"{i}:fixed" in per[f"{i}/fixed"]["fp_safe"]}
        pair = det - still
        other = sum(len(r["fp_unmatched"]) for r in per.values()) / max(len(per), 1)
        n = len(fam)

        def ci(k):
            lo, hi = wilson(k, n)
            return f"{k}/{n} = {k / n:.2f} ({lo:.2f}–{hi:.2f})"
        by = " / ".join(f"{sum(1 for i in pair if fam[i] == f)}/{sum(1 for v in fam.values() if v == f)}" for f in FAMILIES)
        print(f"| {d.name} | {ci(len(det))} | {len(still & det)} of {len(det)} detected; {len(still)} in all | "
              f"{ci(len(pair))} | {by} | {other:.1f} |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
