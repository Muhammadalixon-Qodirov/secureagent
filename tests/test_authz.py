from pathlib import Path

from secagent.authz import idor_candidates, ownership_map
from secagent.config import Config
from secagent.sweep import _python_files, run_sweep
from secagent.tools import ToolRegistry
from secagent.trace import Trace

NOTES = '''
from flask import Flask, abort, request
from flask_login import current_user, login_required
from models import Note, db

app = Flask(__name__)


@app.get("/notes/<int:note_id>")
@login_required
def show(note_id):
    note = Note.query.get_or_404(note_id)
    if note.owner_id != current_user.id:
        abort(403)
    return note.body


@app.post("/notes/<int:note_id>/delete")
@login_required
def delete(note_id):
    note = Note.query.get_or_404(note_id)
    db.session.delete(note)
    db.session.commit()
    return "ok"


@app.post("/notes/share")
@login_required
def share():
    data = request.get_json()
    note = Note.query.filter_by(owner_id=data.get("user_id")).first()
    return note.body


@app.get("/profile")
@login_required
def profile():
    return current_user.name


@app.post("/admin/run")
def run():
    return str(eval(request.form["expr"]))


@app.get("/login")
def login():
    return "form"
'''

MODELS = '''
from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String)


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    body = db.Column(db.String)
'''


def make(tmp_path: Path) -> Path:
    root = tmp_path / "target"
    root.mkdir()
    (root / "app.py").write_text(NOTES, encoding="utf-8")
    (root / "models.py").write_text(MODELS, encoding="utf-8")
    return root


def test_ownership_map_finds_owner_column(tmp_path):
    root = make(tmp_path)
    owned, _ = ownership_map({"models.py": MODELS})
    assert "Note" in owned and "owner_id" in owned["Note"].owner_columns


def test_candidates_idor_request_owner_and_missing_auth(tmp_path):
    root = make(tmp_path)
    cands, _, facts = idor_candidates(root, _python_files(root))
    names = {c.route.function for c in cands}
    assert "delete" in names                       # owned model by id, no owner check
    assert "share" in names                        # owner id taken from the request body
    assert "run" in names                          # eval() without auth while other routes are authenticated
    assert "show" not in names                     # owner compared with current_user
    assert "login" not in names and "profile" not in names
    delete = next(c for c in cands if c.route.function == "delete")
    assert delete.priority == 0 and any(s.function == "show" for s in delete.guarded_siblings)


class Refuses:
    """Model that must not be called (authz-only ablation)."""
    def decide(self, messages, schema=None):
        raise AssertionError("model called")


def test_authz_only_sweep_makes_evidence_backed_findings(tmp_path):
    root = make(tmp_path)
    cfg = Config(authorized_roots=[root])
    reg = ToolRegistry(cfg, Trace(tmp_path / "run"))
    res = run_sweep(cfg, Refuses(), reg, verify=False, authz=True, sweep=False)
    assert res.stats.authz_seeds == 3 and len(res.final.findings) == 3
    for f in res.final.findings:
        ev = f.evidence[0]
        assert f.cwe_id == "CWE-639" and reg.results[ev.tool_event_id].status == "ok"
