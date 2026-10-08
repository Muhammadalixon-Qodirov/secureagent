"""v7 (docs/V7_REJA.md): confirmed-only authorization claims, owner precedent, Python 2 sources,
project word lists, review of changed files only."""

import json

from secagent.config import Config
from secagent.sinks import scan
from secagent.sweep import Candidate, SweepReply, run_sweep
from secagent.tools import ToolRegistry
from secagent.trace import Trace

PY2 = '''import os

class Handler:
    def get(self, name):
        print "serving", name
        try:
            return open("/srv/files/" + name).read()
        except IOError, e:
            print e
'''

NOTES = '''
from flask import Flask, abort, session
from flask_login import login_required, current_user

app = Flask(__name__)


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    body = db.Column(db.String)


@app.route("/notes/<int:note_id>")
@login_required
def show(note_id):
    note = Note.query.get_or_404(note_id)
    if note.owner_id != current_user.id:
        abort(404)
    return note.body


@app.route("/notes/<int:note_id>/raw")
@login_required
def raw(note_id):
    note = Note.query.get_or_404(note_id)
    return note.body


@app.route("/notes/<int:note_id>/export")
@login_required
def export(note_id):
    return open("/srv/exports/" + str(note_id)).read()
'''


class Model:
    """Sweep stand-in lists the given candidates on the first window; verifier answers by handler name."""

    def __init__(self, sweep, verdicts):
        self.sweep, self.verdicts, self.asked = sweep, verdicts, []

    def decide(self, messages, schema=None):
        user = messages[-1]["content"]
        if user.startswith("CLAIM"):
            head = user.split("\n")[0]
            self.asked.append(head)
            name = next(k for k in self.verdicts if k in head)
            return type("R", (), {"content": json.dumps(self.verdicts[name])})()
        out, self.sweep = self.sweep, []
        return type("R", (), {"content": SweepReply(candidates=out).model_dump_json()})()


def line_of(text, needle):
    return text.splitlines().index(needle) + 1


def review(tmp_path, model, **kw):
    root = tmp_path / "t"
    root.mkdir(exist_ok=True)
    (root / "app.py").write_text(NOTES, encoding="utf-8")
    cfg = Config(authorized_roots=[root])
    return run_sweep(cfg, model, ToolRegistry(cfg, Trace(tmp_path / "run")), authz=True, resolve=True, sinks=True,
                     v7=True, **kw)


def test_python2_source_is_scanned_through_lib2to3():
    assert scan({"server.py": PY2}) == []                                  # v5/v6: ast cannot read it
    seeds = scan({"server.py": PY2}, py2=True)
    assert [(s.func, s.line, s.family) for s in seeds] == [("get", 7, "path_traversal")]


def test_project_word_lists_extend_sources_and_sanitizers():
    src = ("def load(job):\n    name = job.blob_key\n    return open('/srv/' + name).read()\n"
           "def load_clean(job):\n    name = scrub(job.blob_key)\n    return open('/srv/' + name).read()\n")
    assert scan({"w.py": src}) == []
    seeds = scan({"w.py": src}, extra={"sources": ["blob_key"], "sanitizers": ["scrub"]})
    assert [s.func for s in seeds] == ["load"]


def test_authorization_claims_are_reported_only_when_confirmed(tmp_path):
    raw_line = line_of(NOTES, "def raw(note_id):") + 1
    show_line = line_of(NOTES, "def show(note_id):") + 1
    model = Model(
        sweep=[Candidate(family="authorization_idor", reason="loads a note by id", line=show_line, title="IDOR in show")],
        verdicts={"raw": {"analysis": "cannot tell", "verdict": "inconclusive"}},
    )
    res = review(tmp_path, model)
    titles = [f.title for f in res.final.findings]
    assert not any("raw" in t or "show" in t for t in titles)              # unconfirmed and owner-scoped: not reported
    assert res.stats.authz_excluded == 1 and res.stats.authz_unconfirmed == 1
    assert not any("IDOR in show" in a for a in model.asked)               # the precedent needed no model call
    reasons = " | ".join(h.reason for h in res.final.coverage.hypotheses if h.analysis_status == "rejected")
    assert "owner check found by the authorization analysis" in reasons and "not confirmed by the verifier" in reasons
    asked = next(m for m in model.asked if "raw" in m)
    assert asked and raw_line                                               # the seed on `raw` went to the verifier


def test_confirmed_authorization_claim_is_reported_with_project_idioms_shown(tmp_path):
    seen = []

    class Recording(Model):
        def decide(self, messages, schema=None):
            seen.append(messages[-1]["content"])
            return super().decide(messages, schema)

    model = Recording(sweep=[], verdicts={"raw": {"analysis": "any user reads any note", "verdict": "vulnerable"}})
    res = review(tmp_path, model)
    assert any("raw" in f.title for f in res.final.findings)
    prompt = next(x for x in seen if x.startswith("CLAIM") and "raw" in x.split("\n")[0])
    assert "PROJECT SECURITY IDIOMS" in prompt and "Flask idioms" in prompt


def test_review_of_a_change_reports_only_in_the_changed_files(tmp_path):
    root = tmp_path / "t"
    root.mkdir()
    (root / "other.py").write_text("def f(request):\n    return open('/srv/' + request.args['n']).read()\n", encoding="utf-8")
    model = Model(sweep=[], verdicts={"raw": {"analysis": "x", "verdict": "inconclusive"}})
    everything = review(tmp_path, model, sweep=False)
    changed = review(tmp_path, Model(sweep=[], verdicts={"raw": {"analysis": "x", "verdict": "inconclusive"}}),
                     sweep=False, only={"other.py"})
    assert {f.evidence[0].file for f in everything.final.findings} == {"app.py", "other.py"}
    assert {f.evidence[0].file for f in changed.final.findings} == {"other.py"}
