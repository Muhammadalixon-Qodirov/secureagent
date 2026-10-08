"""v6 (docs/V6_REJA.md): five-verdict verifier, context by name, retry on an unusable reply."""

import json

from secagent.config import Config
from secagent.sweep import run_sweep
from secagent.tools import ToolRegistry
from secagent.trace import Trace

APP = '''
import sqlite3


def is_allowed(column):
    return column in ("name", "created")


def find_user(conn, username):
    return conn.execute("SELECT * FROM users WHERE name = '%s'" % username).fetchone()


def sorted_users(conn, column):
    if not is_allowed(column):
        raise ValueError(column)
    return conn.execute("SELECT * FROM users ORDER BY %s" % column).fetchall()
'''


class Scripted:
    """Verifier stand-in: answers by the function named in the claim; records what it was shown."""

    def __init__(self, script):
        self.script, self.prompts = script, []

    def decide(self, messages, schema=None):
        user = messages[-1]["content"] if messages[-1]["content"].startswith("CLAIM") else messages[-2]["content"]
        self.prompts.append(messages)
        func = next(k for k in self.script if k in user.split("\n")[0])
        step = self.script[func].pop(0) if len(self.script[func]) > 1 else self.script[func][0]
        return type("R", (), {"content": step if isinstance(step, str) else json.dumps(step)})()


def run(tmp_path, script):
    root = tmp_path / "t"
    root.mkdir()
    (root / "app.py").write_text(APP, encoding="utf-8")
    cfg = Config(authorized_roots=[root])
    model = Scripted(script)
    res = run_sweep(cfg, model, ToolRegistry(cfg, Trace(tmp_path / "run")), sweep=False, sinks=True, v6=True)
    return res, model


def test_verifier_is_shown_the_function_it_names_and_may_then_withdraw(tmp_path):
    guard_line = APP.splitlines().index('    return column in ("name", "created")') + 1
    res, model = run(tmp_path, {
        "find_user": [{"analysis": "value formatted into SQL", "verdict": "vulnerable"}],
        "sorted_users": [
            {"analysis": "is_allowed decides", "verdict": "inconclusive", "need_symbol": "is_allowed"},
            {"analysis": "allow-list of two column names", "verdict": "protected", "control_line": guard_line},
        ],
    })
    assert [f.title for f in res.final.findings] == ["SQL injection in find_user"]
    assert res.stats.symbol_requests == 1 and res.stats.verdicts == {"vulnerable": 1, "protected": 1}
    second = next(m for m in model.prompts if "REQUESTED is_allowed" in m[-1]["content"])
    assert 'return column in ("name", "created")' in second[-1]["content"]
    rejected = [h for h in res.final.coverage.hypotheses if h.analysis_status == "rejected"]
    assert len(rejected) == 1 and "sorted_users" in rejected[0].question


def test_inconclusive_without_a_control_line_is_kept_with_low_confidence(tmp_path):
    res, _ = run(tmp_path, {
        "find_user": [{"analysis": "cannot tell", "verdict": "inconclusive"}],
        "sorted_users": [{"analysis": "looks fine", "verdict": "protected"}],     # no control line: not a withdrawal
    })
    assert len(res.final.findings) == 2
    assert all(f.confidence == "low" for f in res.final.findings)
    assert res.stats.verifier_withdrawn == 0


def test_unusable_verifier_reply_is_asked_for_once_more(tmp_path):
    res, model = run(tmp_path, {
        "find_user": ["this is not json", {"analysis": "formatted into SQL", "verdict": "bypassable"}],
        "sorted_users": [{"analysis": "x", "verdict": "inconclusive"}],
    })
    assert any("SQL injection in find_user" == f.title for f in res.final.findings)
    assert any("not valid JSON" in m[-1]["content"] for m in model.prompts)
    assert res.stats.verifier_failed == 0


def test_sarif_export_has_one_result_per_finding_with_rule_and_region(tmp_path):
    from secagent.sarif import to_sarif
    res, _ = run(tmp_path, {
        "find_user": [{"analysis": "formatted into SQL", "verdict": "vulnerable"}],
        "sorted_users": [{"analysis": "cannot tell", "verdict": "inconclusive"}],
    })
    doc = to_sarif(res.final, "v6")
    run_ = doc["runs"][0]
    assert doc["version"] == "2.1.0" and run_["tool"]["driver"]["name"] == "secagent"
    assert [r["id"] for r in run_["tool"]["driver"]["rules"]] == ["CWE-89"]
    assert len(run_["results"]) == len(res.final.findings) == 2
    r = run_["results"][0]
    region = r["locations"][0]["physicalLocation"]["region"]
    assert r["ruleId"] == "CWE-89" and region["startLine"] >= 1 and "execute" in region["snippet"]["text"]
    assert {x["properties"]["confidence"] for x in run_["results"]} == {"medium", "low"}
