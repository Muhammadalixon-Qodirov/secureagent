"""Deterministic authorization analysis for IDOR candidates (v3).

Idea from MOCGuard (IEEE S&P 2025) and BolaRay (CCS 2024): the data model says
which objects belong to a user; every handler that loads or changes such an
object by a request-supplied id must constrain it to the current user. Plus a
consistency signal (RoleCast/MACE): if other handlers that touch the same model
do check ownership, the one that does not is suspicious.

Everything here is AST/regex analysis of the authorized source tree — no model
calls. Output is *candidates with reasons*; the verifier decides (public by
design? checked elsewhere?).

Works for Flask (`@app.get('/x/<int:id>')`, Flask-Login, `before_request`) and
FastAPI (`@router.get('/x/{id}')`, `Depends(get_current_user)`), with
SQLAlchemy / Flask-SQLAlchemy / SQLModel models or raw `CREATE TABLE` SQL.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

OWNER_COLUMNS = re.compile(
    r"^(owner|user|author|creator|created_by|account|customer|tenant|org|organization|member|"
    r"borrower|buyer|seller|doctor|patient|landlord|tenant_user|assignee|uploader|requester)(_id|_uuid)?$")
USER_TABLE_NAMES = re.compile(r"^(user|users|account|accounts|member|members|customer|customers|app_user|appuser)$", re.I)
PASSWORD_COLUMNS = re.compile(r"^(password|password_hash|hashed_password|passwd|pw_hash)$", re.I)
CURRENT_USER = re.compile(
    r"current_user|get_current_user|session\s*\[\s*['\"](uid|user_id|user)['\"]\s*\]|session\.get\(\s*['\"](uid|user_id|user)|"
    r"g\.user|request\.user|current_user_id\(\)|auth_user|user\.id\b|me\.id\b")
ROLE_WORDS = re.compile(r"admin|role|permission|is_staff|is_superuser|has_role|require_role|superuser", re.I)
LOGIN_WORDS = re.compile(r"login_required|jwt_required|auth_required|authenticated|get_current_user|current_active_user|require_login|token_required", re.I)
ID_PARAM = re.compile(r"(id$|_uuid$|^pk$|^slug$)", re.I)       # id, note_id, pid, userId, ...
PERSONAL_COLUMNS = re.compile(r"^(phone|phone_number|address|email|ssn|dob|date_of_birth|salary|iban|card_number|passport)$", re.I)
REQUEST_OWNER = re.compile(
    r"(request\.(args|form|json|values|query_params)|\bdata|\bpayload|\bbody|get_json\(\))"
    r"[^\n]*['\"](user_id|owner_id|uid|account_id|customer_id|userId|ownerId)['\"]")
BODY_LOGIN = re.compile(
    r"session\.get\(\s*['\"](logged_in|user_id|uid|user)['\"]|session\[\s*['\"](logged_in|user_id|uid|user)['\"]\s*\]|"
    r"current_user_id\(\)|current_user\.is_authenticated|abort\(\s*401|verify_token|decode_token|jwt\.decode|"
    r"get_current_user\(|token_required|login_required")
PUBLIC_ROUTE = re.compile(r"login|logout|register|signup|sign_up|index|^home$|health|static|about|forgot|reset|token|public|"
                          r"favicon|docs|openapi|^root$|status|ping|version", re.I)
DANGEROUS_SINK = re.compile(r"\beval\(|\bexec\(|subprocess\.|os\.system\(|os\.popen\(|render_template_string\(|"
                            r"etree\.|xml\.dom|pickle\.loads|yaml\.load\(|drop_all\(|DROP\s+TABLE", re.I)
SENSITIVE_BODY = re.compile(r"\.delete\(|DELETE\s+FROM|UPDATE\s+\w+\s+SET|INSERT\s+INTO|\.commit\(\)|subprocess|os\.system|"
                            r"eval\(|exec\(|open\(|send_file|admin|password|secret|token", re.I)
WRITE_HINT = re.compile(r"\.delete\(|session\.delete|DELETE\s+FROM|UPDATE\s+\w+\s+SET|\.commit\(\)|setattr\(", re.I)
ROUTE_ATTRS = {"route", "get", "post", "put", "patch", "delete", "api_route"}

# ---- v4: helper resolution. A helper / dependency is classified from its BODY, not its name.
USER_TOKEN = re.compile(r"\b(user|actor|current_user|principal|me|viewer|requester|request)\b")
OWNER_COMPARE = re.compile(r"\.\w+_id\b\s*(?:[=!]=|not\s+in\b|in\b)|[=!]=\s*[\w.]+\.\w+_id\b|"
                           r"\.(?:owner|user|author|creator|created_by)\b\s*[=!]=|[=!]=\s*[\w.]+\.(?:owner|user|author)\b|"
                           r"\b\w+_id\s*=\s*(?:self\.)?(?:request\.user|current_user|user|actor)\b")
ROLE_CHECK = re.compile(r"\.role\b|\brole\s*(?:[=!]=|in\b|not\s+in\b)|is_admin|is_staff|is_superuser|has_role|"
                        r"require_role|has_perm|is_manager|\bpermissions?\b|\bscopes?\b", re.I)
LOGIN_CHECK = re.compile(r"HTTP_401|status_code\s*=\s*401|abort\(\s*401|jwt\.decode|decode_token|verify_token|"
                         r"oauth2_scheme|get_current_user|credentials|Unauthorized|api_key|x-api-key|"
                         r"is_authenticated|session\.get\(|session\[", re.I)
DENY = re.compile(r"raise\s|abort\(|return\s+False|return\s+None|HTTP_40[134]|40[134]\b|Forbidden|PermissionDenied", re.I)
GATE = re.compile(r"status_code\s*=\s*(?:status\.)?(?:HTTP_)?40[13]|HTTPException\(\s*40[13]|abort\(\s*40[13]|"
                  r"PermissionDenied|Forbidden\(|Unauthorized\(")
USER_PARAM = re.compile(r"user|actor|principal|staff|admin|member|account|viewer|current", re.I)
RANK = {None: 0, "login": 1, "role": 2, "owner": 3}
MAX_HELPERS = 3


@dataclass
class OwnedModel:
    name: str                       # class or table name
    table: str
    owner_columns: list[str]
    via: str                        # how ownership was inferred
    file: str
    line: int


@dataclass
class RouteFacts:
    file: str
    function: str
    line_start: int
    line_end: int
    methods: list[str]
    path: str | None
    id_params: list[str]
    auth: str                       # none | login | role | owner(decorator)
    auth_evidence: list[str]
    models_accessed: list[str]
    owner_constraint: bool
    owner_evidence: list[str]
    writes: bool
    access_line: int = 0            # v4: first line that touches an owned model (0 = unknown)
    helpers: list[tuple[str, str, int, int, str]] = field(default_factory=list)   # v4: name, file, start, end, summary


@dataclass
class IdorCandidate:
    route: RouteFacts
    model: OwnedModel
    reason: str
    priority: int                   # 0 = highest (writes), 1 = reads
    guarded_siblings: list[RouteFacts] = field(default_factory=list)


# ---------------------------------------------------------------- data model

def _call_name(n: ast.AST) -> str:
    if isinstance(n, ast.Call):
        n = n.func
    if isinstance(n, ast.Attribute):
        return n.attr
    if isinstance(n, ast.Name):
        return n.id
    return ""


def _fk_target(call: ast.Call) -> str | None:
    for a in ast.walk(call):
        if isinstance(a, ast.Call) and _call_name(a) == "ForeignKey" and a.args:
            t = a.args[0]
            if isinstance(t, ast.Constant) and isinstance(t.value, str):
                return t.value.split(".")[0]
            if isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name):
                return t.value.id
        if isinstance(a, ast.keyword) and a.arg == "foreign_key" and isinstance(a.value, ast.Constant):
            return str(a.value.value).split(".")[0]          # SQLModel Field(foreign_key="user.id")
    return None


def _class_models(tree: ast.Module, file: str) -> list[dict]:
    out = []
    for c in ast.walk(tree):
        if not isinstance(c, ast.ClassDef):
            continue
        cols, fks, table = [], {}, c.name.lower()
        for st in c.body:
            target, value = None, None
            if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name):
                target, value = st.targets[0].id, st.value
            elif isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name):
                target, value = st.target.id, st.value
            if target == "__tablename__" and isinstance(value, ast.Constant):
                table = str(value.value)
                continue
            if target is None or not isinstance(value, ast.Call):
                continue
            if _call_name(value) in ("Column", "mapped_column", "Field", "relationship"):
                if _call_name(value) != "relationship":
                    cols.append(target)
                fk = _fk_target(value)
                if fk:
                    fks[target] = fk
        if cols:
            out.append({"name": c.name, "table": table, "columns": cols, "fks": fks, "file": file, "line": c.lineno})
    return out


CREATE_TABLE = re.compile(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`\"]?(\w+)[`\"]?\s*\((.*?)\)\s*;?\s*$", re.I | re.S)


def _sql_models(source: str, file: str) -> list[dict]:
    out = []
    for m in re.finditer(r"CREATE\s+TABLE[^;]*?\((?:[^()]|\([^()]*\))*\)", source, re.I | re.S):
        mm = CREATE_TABLE.search(m.group(0))
        if not mm:
            continue
        cols, fks = [], {}
        for part in re.split(r",(?![^()]*\))", mm.group(2)):
            words = part.strip().split()
            if not words or words[0].upper() in ("PRIMARY", "FOREIGN", "UNIQUE", "CONSTRAINT", "CHECK"):
                fk = re.search(r"FOREIGN\s+KEY\s*\((\w+)\)\s*REFERENCES\s+(\w+)", part, re.I)
                if fk:
                    fks[fk.group(1)] = fk.group(2)
                continue
            cols.append(words[0].strip("`\""))
            ref = re.search(r"REFERENCES\s+(\w+)", part, re.I)
            if ref:
                fks[words[0].strip("`\"")] = ref.group(1)
        line = source[:m.start()].count("\n") + 1
        out.append({"name": mm.group(1), "table": mm.group(1), "columns": cols, "fks": fks, "file": file, "line": line})
    return out


SQL_TABLE_REF = re.compile(r"\b(?:FROM|UPDATE|INTO|JOIN)\s+[`\"]?(\w+)", re.I)


def _sql_usage_models(source: str, file: str) -> list[dict]:
    """Apps without a schema in the code: infer owner columns from the queries themselves
    (e.g. "SELECT id, borrower_id FROM loans WHERE id = ?" -> loans has owner column borrower_id)."""
    out: dict[str, dict] = {}
    for m in re.finditer(r"([\"'])((?:SELECT|UPDATE|DELETE|INSERT)\b.*?)\1", source, re.I | re.S):
        sql = m.group(2)
        tables = SQL_TABLE_REF.findall(sql)
        if not tables:
            continue
        idents = set(re.findall(r"\b([a-z_][a-z0-9_]*)\b", sql.lower()))
        cols = sorted(i for i in idents if OWNER_COLUMNS.match(i))
        t = tables[0]
        entry = out.setdefault(t, {"name": t, "table": t, "columns": [], "fks": {}, "file": file,
                                   "line": source[:m.start()].count("\n") + 1})
        entry["columns"] = sorted(set(entry["columns"]) | set(cols))
    return [e for e in out.values() if e["columns"]]


def ownership_map(files: dict[str, str]) -> tuple[dict[str, OwnedModel], set[str]]:
    """files: relative path -> source. Returns (owned models by name/table, user model names)."""
    raw = []
    for rel, src in files.items():
        try:
            raw += _class_models(ast.parse(src), rel)
        except SyntaxError:
            pass
        raw += _sql_models(src, rel)
    known = {m["table"].lower() for m in raw}
    for rel, src in files.items():                  # only for tables with no schema/model in the code
        raw += [m for m in _sql_usage_models(src, rel) if m["table"].lower() not in known]
    users = {m["name"] for m in raw if USER_TABLE_NAMES.match(m["table"]) or USER_TABLE_NAMES.match(m["name"])
             or any(PASSWORD_COLUMNS.match(c) for c in m["columns"])}
    user_keys = {u.lower() for u in users} | {m["table"].lower() for m in raw if m["name"] in users}
    owned: dict[str, OwnedModel] = {}
    for m in raw:                                   # direct ownership
        if m["name"] in users:
            continue
        cols = [c for c, t in m["fks"].items() if t.lower() in user_keys]
        cols += [c for c in m["columns"] if OWNER_COLUMNS.match(c) and c not in cols]
        if cols:
            owned[m["name"]] = OwnedModel(m["name"], m["table"], cols, "owner column / FK to user", m["file"], m["line"])
    for m in raw:                                   # personal records: a row about a person is owned by that person
        if m["name"] in owned:
            continue
        personal = [c for c in m["columns"] if PERSONAL_COLUMNS.match(c)]
        if m["name"] in users or len(personal) >= 2:
            owned[m["name"]] = OwnedModel(m["name"], m["table"], [], "personal record (" + ", ".join(personal[:3] or ["user"]) + ")",
                                          m["file"], m["line"])
    for _ in range(2):                              # transitive: FK to an owned model (Comment -> Post -> User)
        keys = {k.lower() for k in owned} | {o.table.lower() for o in owned.values()}
        for m in raw:
            if m["name"] in owned or m["name"] in users:
                continue
            via = [(c, t) for c, t in m["fks"].items() if t.lower() in keys]
            if via:
                c, t = via[0]
                owned[m["name"]] = OwnedModel(m["name"], m["table"], [c], f"FK {c} -> owned {t}", m["file"], m["line"])
    return owned, users


# ---------------------------------------------------------------- routes

def _route_info(fn: ast.FunctionDef) -> tuple[bool, str | None, list[str]]:
    for d in fn.decorator_list:
        if isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr in ROUTE_ATTRS:
            path = d.args[0].value if d.args and isinstance(d.args[0], ast.Constant) else None
            methods = [] if d.func.attr in ("route", "api_route") else [d.func.attr.upper()]
            for kw in d.keywords:
                if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                    methods = [e.value for e in kw.value.elts if isinstance(e, ast.Constant)]
            return True, path if isinstance(path, str) else None, methods or ["GET"]
    return False, None, []


def _path_params(path: str | None) -> list[str]:
    if not path:
        return []
    return [p.split(":")[-1] for p in re.findall(r"<([^>]+)>", path)] + re.findall(r"\{(\w+)(?::[^}]*)?\}", path)


def _decorator_auth(fn: ast.FunctionDef, defs: dict[str, str]) -> tuple[str, list[str]]:
    level, ev = "none", []
    for d in fn.decorator_list:
        name = ast.unparse(d.func if isinstance(d, ast.Call) else d)
        if _call_name(d) in ROUTE_ATTRS:
            continue
        body = defs.get(name.split(".")[-1], "")
        if body and re.search(r"owner|\.user_id|user_id\s*!=|!=\s*current_user", body) and CURRENT_USER.search(body):
            level, ev = "owner", ev + [f"decorator {name} compares owner with the current user"]
        elif ROLE_WORDS.search(name) or (body and ROLE_WORDS.search(body)):
            level = level if level == "owner" else "role"
            ev.append(f"decorator {name} (role)")
        elif LOGIN_WORDS.search(name) or (body and LOGIN_WORDS.search(body)):
            level = level if level in ("owner", "role") else "login"
            ev.append(f"decorator {name} (login)")
    # FastAPI: user = Depends(get_current_user)
    defaults = fn.args.defaults + [d for d in fn.args.kw_defaults if d is not None]
    for dflt in defaults:
        if isinstance(dflt, ast.Call) and _call_name(dflt) in ("Depends", "Security") and dflt.args:
            dep = ast.unparse(dflt.args[0])
            if ROLE_WORDS.search(dep):
                level = level if level == "owner" else "role"
                ev.append(f"Depends({dep}) (role)")
            elif LOGIN_WORDS.search(dep) or "user" in dep.lower() or "auth" in dep.lower():
                level = level if level in ("owner", "role") else "login"
                ev.append(f"Depends({dep}) (login)")
    return level, ev


def _models_accessed(body: str, owned: dict[str, OwnedModel]) -> list[str]:
    hits = []
    for name, om in owned.items():
        cls, tbl = re.escape(name), re.escape(om.table)
        if re.search(rf"\b{cls}\.(query|objects|get|select|filter)|\b{cls}\s*,|select\(\s*{cls}\b|query\(\s*{cls}\b|"
                     rf"\b{cls}\.id\b|get_or_404\(\s*{cls}\b|\bget\(\s*{cls}\b", body) or \
           re.search(rf"(FROM|UPDATE|INTO|DELETE\s+FROM)\s+[`\"]?{tbl}\b", body, re.I):
            hits.append(name)
    return hits


USER_ID_EXPR = (r"(current_user\.id|current_user\b|user\.id|g\.user(\.id)?|me\.id|uid\b|"
                r"session\s*\[\s*['\"]\w+['\"]\s*\]|session\.get\([^)]*\)|current_user_id\(\))")


def _owner_constraint(body: str, owned_cols: set[str]) -> list[str]:
    ev = []
    for col in owned_cols:
        c = re.escape(col)
        if (re.search(rf"\b{c}\b\s*[=!]=\s*[^\n]*{USER_ID_EXPR}", body)
                or re.search(rf"{USER_ID_EXPR}[^\n]*[=!]=\s*[^\n]*\b{c}\b", body)
                or re.search(rf"\b{c}\s*=\s*{USER_ID_EXPR}", body)          # filter_by(owner_id=current_user.id)
                or re.search(rf"\b{c}\s*=\s*[?:%]", body, re.I)):           # SQL: AND owner_id = ?
            ev.append(f"{col} compared with / filtered by the current user")
    # comparison with the current user's id without naming the column (e.g. row[1] != current_user.id)
    if not ev and re.search(rf"[=!]=\s*{USER_ID_EXPR}|{USER_ID_EXPR}\s*[=!]=", body):
        ev.append("compares a value with the current user's id")
    if not ev and re.search(r"is_member\(|has_access\(|can_(view|edit|access)\(|authorize\(|check_owner|ensure_owner", body):
        ev.append("calls an access-check helper")
    return ev


def _classify(body: str, owner_cols: set[str]) -> str | None:
    """What a function's body enforces: owner (compares an owner column / *_id attribute in a function
    that knows the user), role, login, or nothing."""
    cols = "|".join(re.escape(c) for c in owner_cols)
    owner_cmp = OWNER_COMPARE.search(body) or (cols and re.search(rf"\b(?:{cols})\b\s*(?:[=!]=|=\s*\w)", body))
    if owner_cmp and USER_TOKEN.search(body):
        return "owner"
    if ROLE_CHECK.search(body) and DENY.search(body):
        return "role"
    if LOGIN_CHECK.search(body) and DENY.search(body):
        return "login"
    if GATE.search(body) and re.search(r"headers|cookies|token|secret|key", body, re.I):
        return "login"                      # a gate on a request credential, whatever it is called
    return None


def helper_summaries(trees: dict, files: dict[str, str], owner_cols: set[str]) -> dict[str, tuple[str, str, int, int]]:
    """name -> (summary, file, start, end) for project functions that enforce something, callees included
    (two rounds: a loader that calls an owner check is itself an owner check)."""
    info: dict[str, tuple[str | None, str, int, int, set[str]]] = {}
    for rel, tree in trees.items():
        lines = files[rel].splitlines()
        for n in ast.walk(tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name not in info:
                is_route = _route_info(n)[0]
                body = "\n".join(lines[n.lineno - 1:n.end_lineno])
                called = {_call_name(c) for c in ast.walk(n) if isinstance(c, ast.Call)} - {n.name}
                info[n.name] = (None if is_route else _classify(body, owner_cols), rel, n.lineno, n.end_lineno or n.lineno,
                                set() if is_route else called)
    summ = {k: v[0] for k, v in info.items()}
    for _ in range(2):
        for k, (_, _, _, _, called) in info.items():
            best = max([summ[k]] + [summ.get(c) for c in called], key=lambda x: RANK[x])
            summ[k] = best
    out = {k: (summ[k], v[1], v[2], v[3]) for k, v in info.items() if summ[k]}
    for tree in trees.values():             # module-level aliases: require_staff = require_roles(...)
        for st in tree.body:
            if (isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name)
                    and isinstance(st.value, ast.Call) and _call_name(st.value) in out):
                out.setdefault(st.targets[0].id, out[_call_name(st.value)])
    return out


def route_facts(files: dict[str, str], owned: dict[str, OwnedModel], resolve: bool = False) -> list[RouteFacts]:
    defs: dict[str, str] = {}
    trees = {}
    for rel, src in files.items():
        try:
            trees[rel] = ast.parse(src)
        except SyntaxError:
            continue
        lines = src.splitlines()
        for n in ast.walk(trees[rel]):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                defs.setdefault(n.name, "\n".join(lines[n.lineno - 1:n.end_lineno]))
    owner_cols = {c for o in owned.values() for c in o.owner_columns}
    summaries = helper_summaries(trees, files, owner_cols) if resolve else {}
    out = []
    for rel, tree in trees.items():
        lines = files[rel].splitlines()
        file_login = any(isinstance(n, ast.FunctionDef) and any("before_request" in ast.unparse(d) for d in n.decorator_list)
                         for n in ast.walk(tree))
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            is_route, path, methods = _route_info(fn)
            if not is_route:
                continue
            start = min([d.lineno for d in fn.decorator_list] + [fn.lineno])
            body = "\n".join(lines[fn.lineno - 1:fn.end_lineno])
            # include one level of same-project helpers called from the handler
            called = {_call_name(c) for c in ast.walk(fn) if isinstance(c, ast.Call)}
            helper_text = "\n".join(defs[c] for c in called if c in defs and c != fn.name)
            args = [a.arg for a in fn.args.args + fn.args.kwonlyargs]
            id_params = sorted({p for p in _path_params(path) + args if ID_PARAM.search(p)})
            auth, auth_ev = _decorator_auth(fn, defs)
            if auth == "none" and file_login:
                auth, auth_ev = "login", ["before_request hook in this file (login)"]
            if auth == "none" and BODY_LOGIN.search(body):
                auth, auth_ev = "login", ["authentication check inside the handler body"]
            models = _models_accessed(body + "\n" + helper_text, owned)
            owner_ev = _owner_constraint(body + "\n" + helper_text, owner_cols)
            # a helper that checks a parent (e.g. org membership) does not scope the object itself
            helper_only = owner_ev == ["calls an access-check helper"]
            m_req = REQUEST_OWNER.search(body)
            if m_req:
                owner_ev = ["owner id taken from the request, not from the session"]
                helper_only = True
                id_params = sorted(set(id_params) | {f"{m_req.group(m_req.lastindex)} (request data)"})
            writes =bool(set(methods) & {"POST", "PUT", "PATCH", "DELETE"}) or bool(WRITE_HINT.search(body))
            helpers, access_line = [], 0
            if resolve:
                deps = {_call_name(d.args[0]) for d in fn.args.defaults + [k for k in fn.args.kw_defaults if k is not None]
                        if isinstance(d, ast.Call) and _call_name(d) in ("Depends", "Security") and d.args}
                # an injected parameter that is the acting user implies authentication even when the
                # dependency cannot be resolved (imported factory, class instance)
                pos = fn.args.args[len(fn.args.args) - len(fn.args.defaults):] if fn.args.defaults else []
                injected = [a for a, d in list(zip(pos, fn.args.defaults)) + list(zip(fn.args.kwonlyargs, fn.args.kw_defaults))
                            if isinstance(d, ast.Call) and _call_name(d) in ("Depends", "Security")]
                if auth == "none" and any(USER_PARAM.search(a.arg) or (a.annotation is not None
                                          and USER_PARAM.search(ast.unparse(a.annotation))) for a in injected):
                    auth, auth_ev = "login", ["an injected dependency provides the acting user"]
                for name in sorted((called | deps) & set(summaries)):
                    kind, hf, ha, hb = summaries[name]
                    helpers.append((name, hf, ha, hb, kind))
                kinds = {h[4] for h in helpers}
                if "owner" in kinds and not m_req:
                    owner_ev = [f"calls {h[0]} ({h[1]}:{h[2]}), which compares the object's owner with the user"
                                for h in helpers if h[4] == "owner"]
                    helper_only = False
                if auth != "owner" and ("role" in kinds or (ROLE_CHECK.search(body) and DENY.search(body))):
                    auth, auth_ev = "role", auth_ev + ["role check in the handler body or in a called helper"]
                elif auth == "none" and "login" in kinds:
                    auth, auth_ev = "login", [f"calls {h[0]}, which rejects unauthenticated requests"
                                              for h in helpers if h[4] == "login"]
                helpers.sort(key=lambda h: -RANK[h[4]])
                access = [m for m in models if m in owned]
                for i, ln in enumerate(lines[fn.lineno - 1:fn.end_lineno], fn.lineno):
                    if _models_accessed(ln, {m: owned[m] for m in access}):
                        access_line = i
                        break
            out.append(RouteFacts(rel, fn.name, start, fn.end_lineno, methods, path, id_params, auth, auth_ev,
                                  models, (bool(owner_ev) and not helper_only) or auth == "owner", owner_ev, writes,
                                  access_line, helpers[:MAX_HELPERS]))
    return out


# ---------------------------------------------------------------- candidates

def idor_candidates(root: Path, py_files: list[Path], resolve: bool = False
                    ) -> tuple[list[IdorCandidate], dict[str, OwnedModel], list[RouteFacts]]:
    """resolve=True is v4: helpers and dependencies are classified from their bodies (helper_summaries)."""
    files = {}
    for p in py_files:
        try:
            files[p.relative_to(root).as_posix()] = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    owned, _ = ownership_map(files)
    facts = route_facts(files, owned, resolve)
    cands = []
    for r in facts:
        if not r.id_params or not r.models_accessed or r.owner_constraint or (r.auth == "role" and not resolve):
            continue
        for mname in r.models_accessed:
            siblings = [s for s in facts if s is not r and mname in s.models_accessed and s.owner_constraint]
            # v4: a role check alone does not scope the object. Role-gated handlers are candidates only
            # when sibling handlers on the same model do scope it (consistency); otherwise the model is
            # treated as role-managed by design.
            if resolve and r.auth == "role" and not siblings:
                continue
            reason = (f"{','.join(r.methods)} {r.path or r.function}: loads/changes owned model {mname} "
                      f"({owned[mname].via}: {', '.join(owned[mname].owner_columns)}) by request id "
                      f"{', '.join(r.id_params)}; auth: {r.auth} ({'; '.join(r.auth_evidence) or 'none'}); "
                      f"no comparison of the owner with the current user found in the handler"
                      + (f"; {len(siblings)} other handler(s) on {mname} do check ownership" if siblings else ""))
            cands.append(IdorCandidate(r, owned[mname], reason, 0 if r.writes else 1, siblings[:2]))
            break
    cands += _missing_auth_candidates(facts, files, {id(c.route) for c in cands})
    cands.sort(key=lambda c: (c.priority, c.route.file, c.route.line_start))
    return cands, owned, facts


MISSING_AUTH = OwnedModel("(endpoint)", "", [], "missing authentication", "", 0)


def _missing_auth_candidates(facts: list[RouteFacts], files: dict[str, str], taken: set[int]) -> list[IdorCandidate]:
    """Consistency (RoleCast/MACE): when most routes of the app require authentication, a route
    that does something sensitive without any is suspicious."""
    if len(facts) < 3:
        return []
    authed = [r for r in facts if r.auth != "none"]
    if not authed:
        return []
    mostly_authed = len(authed) / len(facts) >= 0.5
    out = []
    for r in facts:
        if r.auth != "none" or id(r) in taken or PUBLIC_ROUTE.search(r.function) or PUBLIC_ROUTE.search(r.path or ""):
            continue
        body = "\n".join(files[r.file].splitlines()[r.line_start - 1:r.line_end])
        dangerous = bool(DANGEROUS_SINK.search(body))      # strong signal: any authenticated route is enough
        if not dangerous and not (mostly_authed and (r.writes or (r.models_accessed and r.id_params)
                                                     or SENSITIVE_BODY.search(body))):
            continue
        reason = (f"{','.join(r.methods)} {r.path or r.function}: no authentication check, while "
                  f"{len(authed)} of {len(facts)} routes in this app require it (e.g. "
                  f"{', '.join(a.function for a in authed[:3])}); the handler performs a sensitive operation")
        out.append(IdorCandidate(r, MISSING_AUTH, reason, 1, authed[:2]))
    return out


def render_facts(r: RouteFacts) -> str:
    own = "owner check: yes (" + "; ".join(r.owner_evidence) + ")" if r.owner_constraint else "owner check: none found"
    return (f"auth={r.auth}; id params={','.join(r.id_params) or 'none'}; owned models touched="
            f"{','.join(r.models_accessed) or 'none'}; {own}")
