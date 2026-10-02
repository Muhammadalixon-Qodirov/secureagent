"""CLI.

    python -m secagent review --target targets/demo_app [--config config.yaml] [--single-pass]

Writes runs/<timestamp>/{trace.jsonl, final.json, report.md, result.json} (+ per-pass model replies).
Exit code: 0 complete, 1 partial, 2 blocked / error.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from .report import render
from .review import run_review
from .sweep import run_sweep
from .config import Config, load_config
from .model import OllamaModel
from .tools import ToolRegistry
from .trace import Trace

ROOT = Path(__file__).resolve().parent.parent


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="secagent")
    sub = ap.add_subparsers(dest="cmd", required=True)
    rv = sub.add_parser("review", help="review a codebase you are authorized to review")
    rv.add_argument("--target", type=Path, help="authorized root (overrides config authorized_roots)")
    rv.add_argument("--config", type=Path)
    rv.add_argument("--mode", choices=["v2", "v1"], default="v2",
                    help="v2: coverage sweep + verifier (default); v1: tool-using agent loop")
    rv.add_argument("--single-pass", action="store_true", help="v1 only: one open-ended pass instead of one per family")
    rv.add_argument("--no-verify", action="store_true", help="skip the independent verifier (ablation)")
    rv.add_argument("--run-dir", type=Path)
    rv.add_argument("--seed", type=int, default=0)
    a = ap.parse_args(argv)

    data = load_config(a.config).model_dump() if a.config else {}
    if a.target:
        data["authorized_roots"] = [a.target]
    try:
        config = Config.model_validate(data)
    except Exception as exc:
        print(f"invalid configuration: {exc}", file=sys.stderr)
        return 2

    run_dir = a.run_dir or ROOT / "runs" / datetime.now().strftime("%Y%m%d-%H%M%S")
    registry = ToolRegistry(config, Trace(run_dir))
    model = OllamaModel(config, seed=a.seed)
    if a.mode == "v2":
        sw = run_sweep(config, model, registry, verify=not a.no_verify, run_dir=run_dir)
        final, notes = sw.final, sw.notes
        summary = {"mode": "v2", "status": final.status, "findings": len(final.findings), "stats": sw.stats.__dict__,
                   "tool_reliability": registry.trace.reliability()}
    else:
        res = run_review(config, model, registry, run_dir, single_pass=a.single_pass, verify=not a.no_verify)
        final = res.final
        notes = [f"[{name}] {n}" for name, r in res.passes.items() for n in r.controller_notes]
        summary = {"mode": "v1", "status": final.status, "findings": len(final.findings),
                   "passes": {name: {"status": r.final.status, "stop_reason": r.stop_reason,
                                     "findings": len(r.final.findings), "stats": r.stats.__dict__,
                                     "controller_notes": r.controller_notes} for name, r in res.passes.items()},
                   "tool_reliability": registry.trace.reliability()}
    (run_dir / "result.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    meta = {"model": config.model, "context": config.max_context_tokens,
            "mode": "v2 coverage sweep" if a.mode == "v2" else ("v1 single pass" if a.single_pass else "v1 per family"),
            "verifier": "off" if a.no_verify else "on", "families": ", ".join(config.enabled_families)}
    (run_dir / "report.md").write_text(render(final, Path(config.authorized_roots[0]).name, meta, notes),
                                       encoding="utf-8")
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    for f in final.findings:
        ev = f.evidence[0]
        print(f"- [{f.severity}/{f.confidence}] {f.cwe_id} {f.title} @ {ev.file}:{ev.line_start}")
    print(f"run dir: {run_dir}")
    return {"complete": 0, "partial": 1}.get(final.status, 2)


if __name__ == "__main__":
    sys.exit(main())
