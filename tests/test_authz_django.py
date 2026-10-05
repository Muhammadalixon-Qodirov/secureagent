"""v4: helper resolution and Django views, checked against the synthetic dev apps (eval/dev_django/EXPECTED.md)."""

from pathlib import Path

from secagent.authz import idor_candidates
from secagent.config import Config
from secagent.sweep import _python_files, run_sweep
from secagent.tools import ToolRegistry
from secagent.trace import Trace

DEV = Path(__file__).resolve().parent.parent / "eval" / "dev_django"


def cands(app: str, resolve: bool = True):
    root = DEV / app
    c, owned, facts = idor_candidates(root, _python_files(root), resolve=resolve)
    return {x.route.function: x for x in c}, owned, {r.function: r for r in facts}


def test_clinic_function_views_and_viewsets():
    c, owned, facts = cands("clinic")
    assert set(owned) == {"Appointment", "Invoice", "Note"}             # Clinic has no owner
    assert set(c) == {"appointment_detail", "edit_note", "InvoiceViewSet", "purge_invoices"}
    assert c["purge_invoices"].model.name == "(endpoint)"               # missing authentication, not BOLA
    assert facts["my_appointment"].owner_constraint                     # patient=request.user in the lookup
    assert facts["cancel_appointment"].owner_constraint                 # appt.patient != request.user
    assert "note_for_user" in facts["note_detail"].owner_evidence[0]    # owner check lives in a helper
    assert facts["MyInvoiceViewSet"].owner_constraint                   # get_queryset filters by the user
    assert "IsInvoiceOwner" in facts["GuardedInvoiceViewSet"].owner_evidence[0]
    assert "note_for_user" not in facts                                 # not routed: not a view
    assert c["InvoiceViewSet"].route.access_line == 67                  # evidence points at the queryset line


def test_desk_class_views_api_views_and_roles():
    c, owned, facts = cands("desk")
    assert set(c) == {"TicketCloseView", "AttachmentAPI", "reassign"}
    assert facts["AttachmentAPI"].auth == "login"                       # only the settings default
    assert facts["article"].auth == "none"                              # AllowAny overrides the default
    assert facts["delete_ticket"].auth == "role" and facts["StaffTicketListView"].auth == "role"
    assert "can_see_ticket" in facts["TicketView"].owner_evidence[0]
    assert not facts["AttachmentAPI"].owner_constraint                  # .objects.get() is not TicketView.get
    assert any("request data" in p for p in facts["reassign"].id_params)


def test_v3_mode_ignores_django(tmp_path):
    c, _, facts = cands("clinic", resolve=False)
    assert not facts and not c                                          # v3 has no Django support


FASTAPI = '''
import os
from fastapi import APIRouter, Depends, HTTPException, Request

router = APIRouter()


def _gate(request: Request) -> None:
    if request.headers.get("x-internal-token") != os.environ.get("TOKEN"):
        raise HTTPException(status_code=403, detail="forbidden")


def get_current_user(request: Request):
    if "uid" not in request.session:
        raise HTTPException(status_code=401)
    return request.session["uid"]


def require_roles(*roles):
    def _checker(user=Depends(get_current_user)):
        if user.role not in roles:
            raise HTTPException(status_code=403)
        return user
    return _checker


require_staff = require_roles("admin", "agent")


@router.get("/me")
def me(user=Depends(get_current_user)):
    return user


@router.get("/a")
def a(user=Depends(get_current_user)):
    return user


@router.post("/ops/rebuild")
def rebuild(gate: None = Depends(_gate)):
    os.system("make rebuild")
    return {"ok": True}


@router.post("/articles")
def create_article(payload: dict, current=Depends(require_staff)):
    return payload


@router.post("/ops/run")
def run(cmd: str):
    os.system(cmd)
    return {"ok": True}
'''


def test_dependencies_are_classified_from_their_bodies(tmp_path):
    root = tmp_path / "t"
    root.mkdir()
    (root / "app.py").write_text(FASTAPI, encoding="utf-8")
    v3, _, _ = idor_candidates(root, _python_files(root))
    v4, _, facts = idor_candidates(root, _python_files(root), resolve=True)
    assert {x.route.function for x in v3} == {"rebuild", "run"}         # v3: opaque gate name -> "no auth"
    assert {x.route.function for x in v4} == {"run"}                    # v4: the gate's body rejects with 403
    by = {r.function: r for r in facts}
    assert by["rebuild"].auth == "login" and by["create_article"].auth == "role"   # alias of a role factory


AUDITED = '''
from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy import Column, ForeignKey, Integer, String

app = FastAPI()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)


class Ticket(Base):
    __tablename__ = "tickets"
    id = Column(Integer, primary_key=True)
    owner_id = Column(Integer, ForeignKey("users.id"))
    body = Column(String)


class AuditLog(Base):
    __tablename__ = "audit"
    id = Column(Integer, primary_key=True)
    owner_id = Column(Integer, ForeignKey("users.id"))


def get_current_user(token: str = Depends(oauth2_scheme)):
    user = decode_token(token)
    if user is None:
        raise HTTPException(status_code=401)
    return user


def audit(db, actor, action):
    db.add(AuditLog(owner_id=actor.id if actor else None, action=action))


def ticket_for(db, user, ticket_id):
    ticket = db.get(Ticket, ticket_id)
    if ticket is None or ticket.owner_id != user.id:
        raise HTTPException(status_code=404)
    return ticket


@app.put("/tickets/{ticket_id}")
def update_ticket(ticket_id: int, body: str, db=Depends(get_db), user=Depends(get_current_user)):
    ticket = db.get(Ticket, ticket_id)
    ticket.body = body
    audit(db, user, "ticket.update")
    db.commit()
    return ticket


@app.delete("/tickets/{ticket_id}")
def delete_ticket(ticket_id: int, db=Depends(get_db), user=Depends(get_current_user)):
    ticket = ticket_for(db, user, ticket_id)
    db.delete(ticket)
    audit(db, user, "ticket.delete")
    db.commit()
'''


def test_audit_helper_is_not_an_owner_check(tmp_path):
    root = tmp_path / "t"
    root.mkdir()
    (root / "app.py").write_text(AUDITED, encoding="utf-8")
    v4, _, facts = idor_candidates(root, _python_files(root), resolve=True)
    by = {r.function: r for r in facts}
    assert not by["update_ticket"].owner_constraint         # AuditLog(owner_id=actor.id) records the actor only
    assert by["delete_ticket"].owner_constraint and "ticket_for" in by["delete_ticket"].owner_evidence[0]
    assert {x.route.function for x in v4} == {"update_ticket"}


class HelperAware:
    """Verifier stand-in: withdraws when a shown helper contains the owner comparison."""
    def __init__(self):
        self.prompts = []

    def decide(self, messages, schema=None):
        self.prompts.append(messages[-1]["content"])
        return type("R", (), {"content": '{"analysis": "kept", "claim_holds": true, "control_file": null, "control_line": null}'})()


def test_v4_verifier_gets_facts_and_whole_handler(tmp_path):
    root = DEV / "desk"
    cfg = Config(authorized_roots=[root])
    model = HelperAware()
    res = run_sweep(cfg, model, ToolRegistry(cfg, Trace(tmp_path / "run")), verify=True, authz=True, sweep=False,
                    harden=True, resolve=True)
    assert len(res.final.findings) == 3 and len(model.prompts) == 3
    assert all("AUTHZ FACTS" in p for p in model.prompts)
    close = next(f for f in res.final.findings if "TicketCloseView" in f.title)
    assert "get_object_or_404(Ticket" in close.evidence[0].excerpt      # evidence is the access line, not the class line
