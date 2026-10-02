import json
from pathlib import Path

from secagent.config import Config
from secagent.review import family_task, merge, run_review
from secagent.schemas import FinalDecision
from secagent.tools import ToolRegistry
from secagent.trace import Trace

from test_agent import APP, REF, UPDATE, ScriptedModel, final, finding, read_action


def test_family_task_uses_card_questions():
    t = family_task("authorization_idor")
    assert "CWE-639" in t and "what proves the current user may act on *this* object" in t


def test_merge_prefixes_ids_and_dedupes():
    a = FinalDecision.model_validate(final([finding()]))
    b = FinalDecision.model_validate(final([finding()], status="partial"))
    m = merge({"sql_injection": a, "authorization_idor": b})
    assert [f.id for f in m.findings] == ["SQLI-F001"]
    assert m.findings[0].hypothesis_ids == ["SQLI-H001"]
    assert m.status == "partial"
    assert any("duplicate" in x for x in m.limitations)
    assert {u.id for u in m.hypothesis_updates} == {"SQLI-H001", "AUTHZ-H001"}


def test_run_review_one_pass_per_family_shares_event_ids(tmp_path: Path):
    root = tmp_path / "target"
    (root / "app").mkdir(parents=True)
    (root / "app" / "views.py").write_text(APP, encoding="utf-8")
    config = Config(authorized_roots=[root], enabled_families=["sql_injection", "path_traversal"])
    registry = ToolRegistry(config, Trace(tmp_path / "run"))
    pass2_final = final([], updates=[])
    model = ScriptedModel([read_action(), final([finding()]),          # sql_injection pass: E0001
                           read_action(start=1, end=5), pass2_final])   # path_traversal pass: E0002
    res = run_review(config, model, registry, tmp_path / "run", verify=False)
    assert list(res.passes) == ["sql_injection", "path_traversal"]
    assert [f.id for f in res.final.findings] == ["SQLI-F001"]
    assert set(registry.results) == {"E0001", "E0002"}                # one id sequence across passes
    assert "ONE vulnerability family only: Path traversal" in model.seen[2][1]["content"]
    assert json.loads((tmp_path / "run" / "final.json").read_text(encoding="utf-8"))["findings"][0]["id"] == "SQLI-F001"
