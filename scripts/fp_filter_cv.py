"""Leave-one-app-out evaluation of the learned FP filter (secagent/fpfilter.py) on a dev set.

Candidates come from a saved no-verifier run (e.g. agent_v3_no_verify on RealVuln
Flask). For each app, the filter is trained on the other apps' labelled candidates
and applied to this app's; the kept findings are scored with the normal matching
rule. Compared with: no filter, and the LLM verifier run of the same system.
Finally the filter is fitted on all dev rows and the weights are saved, so a
frozen copy can be applied to the FastAPI test set.

    python scripts/fp_filter_cv.py agent_v3_no_verify [--verifier-run agent_v3]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from secagent import fpfilter  # noqa: E402
from secagent.evaluate import DATASETS, LINE_SLACK, Norm, metrics, score_app  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
RUNS = ROOT / "runs" / "eval_realvuln"
OUT = ROOT / "eval" / "fp_filter"


def label(app: str, f: dict, cases, cwe: dict, matched: set) -> int | None:
    """1 = matches an unmatched vulnerable case, 0 = trap or unmatched, None = duplicate / out of scope."""
    fam = cwe.get(f["cwe_id"] or "")
    if fam is None:
        return None
    for c in cases:
        if c.app != app or c.family != fam:
            continue
        for file, a, b in c.loci:
            if any(file == e["file"] and e["line_start"] <= b + LINE_SLACK and e["line_end"] >= a - LINE_SLACK
                   for e in f["evidence"]):
                if c.id in matched:
                    return None
                matched.add(c.id)
                return int(c.vulnerable)
    return 0


def scored(app: str, findings: list[dict], cases, cwe: dict):
    s = score_app(app, [norm(f) for f in findings], cases, cwe)
    for x in s.fp_unmatched:
        x["family"] = cwe.get(x["cwe"] or "")
    return s


def norm(f: dict) -> Norm:
    return Norm(f["cwe_id"], f["evidence"][0]["file"], [(e["line_start"], e["line_end"]) for e in f["evidence"]], f["title"])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("system")
    ap.add_argument("--verifier-run")
    a = ap.parse_args()
    loader, apps_root, _ = DATASETS["realvuln"]
    cases, cwe = loader()
    apps = sorted({c.app for c in cases})
    rows = {}                                        # app -> list of (finding, x, y)
    for app in apps:
        final = json.loads((RUNS / a.system / app / "final.json").read_text(encoding="utf-8"))
        counts: dict[str, int] = {}
        for f in final["findings"]:
            counts[f["evidence"][0]["file"]] = counts.get(f["evidence"][0]["file"], 0) + 1
        matched: set = set()
        rows[app] = [(f, fpfilter.features(f, apps_root / app, counts), label(app, f, cases, cwe, matched))
                     for f in final["findings"]]

    unfiltered, filtered = {}, {}
    for app in apps:
        train = [(x, y) for other in apps if other != app for _, x, y in rows[other] if y is not None]
        w = fpfilter.fit([x for x, _ in train], [y for _, y in train])
        keep = [f for f, x, _ in rows[app] if fpfilter.predict(w, x) >= fpfilter.THRESHOLD]
        unfiltered[app] = scored(app, [f for f, _, _ in rows[app]], cases, cwe)
        filtered[app] = scored(app, keep, cases, cwe)

    res = {"unfiltered": metrics(unfiltered, cases)["micro"], "learned_filter_loao": metrics(filtered, cases)["micro"]}
    if a.verifier_run:
        res["llm_verifier"] = json.loads((RUNS / a.verifier_run / "scores.json").read_text(encoding="utf-8"))["metrics"]["micro"]
    all_rows = [(x, y) for app in apps for _, x, y in rows[app] if y is not None]
    w_all = fpfilter.fit([x for x, _ in all_rows], [y for _, y in all_rows])
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / f"weights_{a.system}.json").write_text(json.dumps(
        {"trained_on": f"RealVuln Flask, {a.system}, {len(all_rows)} labelled candidates",
         "features": fpfilter.FEATURES, "weights": [round(v, 4) for v in w_all],
         "l2": fpfilter.L2, "epochs": fpfilter.EPOCHS, "threshold": fpfilter.THRESHOLD}, indent=2), encoding="utf-8")
    (OUT / f"cv_{a.system}.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    pos = sum(y for _, y in all_rows)
    print(f"{a.system}: {len(all_rows)} labelled candidates ({pos} TP, {len(all_rows) - pos} FP)")
    for k, m in res.items():
        print(f"  {k:22s} TP={m['tp']:3d} FP={m['fp_lookalike'] + m['fp_unmatched']:3d} "
              f"P={m['precision']} R={m['recall']} F1={m['f1']}")
    print("  weights:", ", ".join(f"{n}={v:+.2f}" for n, v in zip(fpfilter.FEATURES, w_all)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
