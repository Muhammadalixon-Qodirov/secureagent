import json
from pathlib import Path

from secagent.config import Config
from secagent.routes import chunk_file, route_inventory
from secagent.sweep import run_sweep
from secagent.tools import ToolRegistry
from secagent.trace import Trace

from test_agent import APP, ScriptedModel


def cand(line, family="sql_injection", title="SQLi in search"):
    return {"family": family, "reason": "q reaches the f-string", "line": line, "title": title}


def setup(tmp_path: Path, extra_files=None):
    root = tmp_path / "target"
    (root / "app").mkdir(parents=True)
    (root / "app" / "views.py").write_text(APP, encoding="utf-8")
    for rel, text in (extra_files or {}).items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8")
    config = Config(authorized_roots=[root])
    return config, ToolRegistry(config, Trace(tmp_path / "run"))


def test_route_inventory_and_chunks():
    routes = route_inventory(APP, "app/views.py")
    assert [(r.function, r.methods, r.path) for r in routes] == [("search", ["GET"], "/search")]
    assert chunk_file(APP) == [(1, 12)]


def test_every_window_is_read_and_finding_uses_real_line(tmp_path):
    config, reg = setup(tmp_path)
    model = ScriptedModel([{"candidates": [cand(12)]}])
    res = run_sweep(config, model, reg, verify=False)
    assert res.stats.windows == 1 and len(res.final.findings) == 1
    ev = res.final.findings[0].evidence[0]
    assert ev.line_start == 12 and "db.execute" in ev.excerpt and reg.results[ev.tool_event_id].tool == "read_file"
    assert "FILE ROUTES" in model.seen[0][1]["content"] and "/search" in model.seen[0][1]["content"]


def test_candidate_outside_window_is_ignored(tmp_path):
    config, reg = setup(tmp_path)
    res = run_sweep(config, ScriptedModel([{"candidates": [cand(999)]}]), reg, verify=False)
    assert res.final.findings == [] and res.stats.candidates_out_of_window == 1


def test_verifier_withdraws_only_with_control_line_in_window(tmp_path):
    config, reg = setup(tmp_path)
    model = ScriptedModel([{"candidates": [cand(12), cand(9, "authorization_idor", "IDOR")]},
                           {"analysis": "value is bound", "claim_holds": False, "control_line": 12},
                           {"analysis": "unsure", "claim_holds": False, "control_line": None}])
    res = run_sweep(config, model, reg, verify=True)
    assert res.stats.verifier_withdrawn == 1 and res.stats.verifier_kept == 1
    assert [f.confidence for f in res.final.findings] == ["low"]
    assert any(h.analysis_status == "rejected" for h in res.final.coverage.hypotheses)


def test_vendored_and_test_dirs_are_skipped(tmp_path):
    config, reg = setup(tmp_path, {".venv/lib/x.py": "x = 1\n", "tests/test_a.py": "y = 2\n"})
    res = run_sweep(config, ScriptedModel([{"candidates": []}]), reg, verify=False)
    assert res.final.coverage.reviewed_paths == ["app/views.py"]


def test_duplicate_candidates_are_merged(tmp_path):
    config, reg = setup(tmp_path)
    res = run_sweep(config, ScriptedModel([{"candidates": [cand(12), cand(11)]}]), reg, verify=False)
    assert len(res.final.findings) == 1 and res.stats.duplicates == 1
