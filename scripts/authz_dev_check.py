"""Deterministic dev check of authz.idor_candidates against labelled dev data.

Scores only the IDOR family, no model calls. Dev sets only: the synthetic
holdout and the RealVuln Flask set. The FastAPI set is the v3 test set and must
not be used here.

    python scripts/authz_dev_check.py [holdout|realvuln] [-v]
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from secagent.authz import idor_candidates  # noqa: E402
from secagent.evaluate import DATASETS, Norm, score_app  # noqa: E402
from secagent.sweep import _python_files  # noqa: E402

DEV = {"holdout", "realvuln"}


def main() -> int:
    ds = sys.argv[1] if len(sys.argv) > 1 else "holdout"
    verbose = "-v" in sys.argv
    if ds not in DEV:
        raise SystemExit(f"{ds} is not a dev set")
    loader, root, _ = DATASETS[ds]
    cases, cwe = loader()
    tp = fp = fn = 0
    for app in sorted({c.app for c in cases}):
        app_root = root / app
        cands, owned, facts = idor_candidates(app_root, _python_files(app_root))
        norms = [Norm("CWE-639", c.route.file, [(c.route.line_start, c.route.line_end)], c.reason) for c in cands]
        s = score_app(app, norms, [c for c in cases if c.family == "authorization_idor"], cwe)
        tp += len(s.tp); fp += len(s.fp_safe) + len(s.fp_unmatched); fn += len(s.fn)
        if verbose:
            print(f"{app}: owned={sorted(owned)} routes={len(facts)} cands={len(cands)} "
                  f"TP={s.tp} FP={s.fp_safe + [u['file'] + ':' + str(u['ranges'][0][0]) for u in s.fp_unmatched]} FN={s.fn}")
    p = tp / (tp + fp) if tp + fp else 0
    r = tp / (tp + fn) if tp + fn else 0
    print(f"[{ds}] IDOR deterministic candidates: TP={tp} FP={fp} FN={fn}  precision={p:.2f} recall={r:.2f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
