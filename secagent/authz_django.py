"""Django / Django REST framework views for the authorization analysis (v4).

Written from the frameworks' documented conventions and the synthetic apps in
eval/dev_django/ — not from the RealVuln Django targets, which are the v4 test
set (docs/django_protocol.md).

A *unit* is what Flask/FastAPI call a route handler:
- a function view: a module-level function whose first parameter is `request`
  and which is referenced from a urls.py (or any such function when the project
  has no urls.py we can read);
- a class-based view / DRF viewset: the whole class. Generic views and viewsets
  have handlers with no code of their own (`ModelViewSet.retrieve`), so the
  class attributes (`queryset`, `permission_classes`, `get_queryset`) are the
  evidence.
"""

from __future__ import annotations

import ast
import re

VIEW_BASE = re.compile(r"View$|ViewSet$|APIView$|Mixin$|^generics\.|^viewsets\.|^views\.")
DETAIL_BASE = re.compile(r"ModelViewSet|ReadOnlyModelViewSet|Retrieve|Update|Destroy|DetailView|UpdateView|DeleteView|"
                         r"GenericViewSet")
WRITE_BASE = re.compile(r"ModelViewSet|Create|Update|Destroy|DeleteView|CreateView|UpdateView|FormView")
LOGIN_DECOS = re.compile(r"login_required|LoginRequiredMixin|IsAuthenticated\b|authentication_required|"
                         r"TokenHasScope|IsAuthenticatedOrReadOnly")
ROLE_DECOS = re.compile(r"permission_required|user_passes_test|staff_member_required|PermissionRequiredMixin|"
                        r"UserPassesTestMixin|IsAdminUser|DjangoModelPermissions|superuser|[Aa]dmin|[Ss]taff|"
                        r"[Mm]anager|[Rr]ole")
HTTP_METHODS = ("get", "post", "put", "patch", "delete")
VIEWSET_ACTIONS = ("list", "retrieve", "create", "update", "partial_update", "destroy")
DJANGO_WRITE = re.compile(r"\.save\(|\.delete\(|\.update\(|\.create\(|\.bulk_create\(|\.set\(|\.add\(|\.remove\(")
DJANGO_SCOPED = re.compile(r"\w+\s*=\s*(?:self\.)?request\.user\b|(?:self\.)?request\.user\.\w+\.(?:all|filter|get|exclude)\(|"
                           r"(?:self\.)?request\.user\.\w+_set\b|[=!]=\s*(?:self\.)?request\.user\b|"
                           r"(?:self\.)?request\.user\s*[=!]=|(?:self\.)?request\.user\.(?:id|pk)\b\s*[=!]=|"
                           r"[=!]=\s*(?:self\.)?request\.user\.(?:id|pk)\b")
DJANGO_LOGIN_BODY = re.compile(r"request\.user\.is_authenticated|request\.user\.is_anonymous|request\.auth\b")
DJANGO_ROLE_BODY = re.compile(r"request\.user\.(is_staff|is_superuser|has_perm|groups|role)\b|\.has_perm\(")


def is_django(src: str) -> bool:
    return bool(re.search(r"^\s*(from|import)\s+(django|rest_framework)\b", src, re.M))


def url_names(files: dict[str, str]) -> set[str]:
    """Identifiers mentioned in urls.py files: the views that are actually routed."""
    names: set[str] = set()
    for rel, src in files.items():
        if not rel.endswith("urls.py"):
            continue
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        for n in ast.walk(tree):
            if isinstance(n, ast.Name):
                names.add(n.id)
            elif isinstance(n, ast.Attribute):
                names.add(n.attr)
    return names


def global_auth(files: dict[str, str]) -> str:
    """Project-wide default from settings: DRF DEFAULT_PERMISSION_CLASSES or a login-required middleware."""
    for rel, src in files.items():
        if "settings" not in rel:
            continue
        m = re.search(r"DEFAULT_PERMISSION_CLASSES[^\]\)]*", src, re.S)
        if m and "IsAuthenticated" in m.group(0) and "AllowAny" not in m.group(0):
            return "login"
        if re.search(r"LoginRequiredMiddleware", src):
            return "login"
    return "none"


def _deco_names(node) -> list[str]:
    return [ast.unparse(d) for d in getattr(node, "decorator_list", [])]


def _permission_names(cls_or_fn, lines: list[str]) -> list[str]:
    """Names inside permission_classes = [...] / @permission_classes([...])."""
    out = []
    for n in ast.walk(cls_or_fn):
        if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "permission_classes" for t in n.targets):
            out += [ast.unparse(e).split(".")[-1].split("(")[0] for e in getattr(n.value, "elts", [])]
    for d in getattr(cls_or_fn, "decorator_list", []):
        if isinstance(d, ast.Call) and ast.unparse(d.func).endswith("permission_classes") and d.args:
            out += [ast.unparse(e).split(".")[-1].split("(")[0] for e in getattr(d.args[0], "elts", [])]
    return out


def unit_auth(node, body: str, lines: list[str], class_src: dict[str, str], classify, default: str) -> tuple[str, list[str], bool]:
    """(auth level, evidence, owner enforced by a permission class)."""
    level, ev, owner = "none", [], False
    rank = {"none": 0, "login": 1, "role": 2}

    def up(new: str, why: str):
        nonlocal level
        if rank[new] > rank[level]:
            level = new
        ev.append(why)

    bases = [ast.unparse(b) for b in getattr(node, "bases", [])]
    perms = _permission_names(node, lines)
    explicit_public = "AllowAny" in perms
    for text in _deco_names(node) + bases:
        if ROLE_DECOS.search(text) and not text.endswith("api_view") and "csrf" not in text:
            up("role", f"{text.split('(')[0]} (role)")
        elif LOGIN_DECOS.search(text):
            up("login", f"{text.split('(')[0]} (login)")
    for sub in ast.walk(node):                       # method_decorator(login_required) on methods
        if sub is not node and isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for text in _deco_names(sub):
                if ROLE_DECOS.search(text) and "action" not in text.split("(")[0]:
                    up("role", f"{text.split('(')[0]} on {sub.name} (role)")
                elif LOGIN_DECOS.search(text):
                    up("login", f"{text.split('(')[0]} on {sub.name} (login)")
    for name in perms:
        if name in class_src:                        # project permission class: judge by its body
            kind = classify(class_src[name])
            if kind == "owner":
                owner = True
                up("login", f"permission class {name} compares the object's owner with the user")
            elif kind == "role" or ROLE_DECOS.search(name):
                up("role", f"permission class {name} (role)")
            else:
                up("login", f"permission class {name}")
        elif ROLE_DECOS.search(name):
            up("role", f"permission class {name} (role)")
        elif LOGIN_DECOS.search(name):
            up("login", f"permission class {name} (login)")
    m_role = DJANGO_ROLE_BODY.search(body)
    if m_role and re.search(r"raise|Forbidden|redirect\(|return\s+Response\(|PermissionDenied|40[13]|return\s+(self\.)?request", body):
        up("role", f"role check in the view body ({m_role.group(0)})")
    elif DJANGO_LOGIN_BODY.search(body):
        up("login", "authentication check in the view body")
    if level == "none" and default == "login" and not explicit_public:
        up("login", "project default requires authentication (settings)")
    return level, ev, owner


def units(tree: ast.Module, rel: str, routed: set[str]):
    """Yield (node, kind) for views in a module: 'function' or 'class'."""
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = node.args.args
            if args and args[0].arg == "request" and (not routed or node.name in routed) and not node.name.startswith("_"):
                yield node, "function"
        elif isinstance(node, ast.ClassDef):
            bases = [ast.unparse(b) for b in node.bases]
            if any(VIEW_BASE.search(b) for b in bases) and not node.name.endswith("Mixin") \
                    and (not routed or node.name in routed):
                yield node, "class"


def unit_shape(node, kind: str, body: str, id_param) -> tuple[list[str], list[str]]:
    """(HTTP methods, id parameters) of a unit."""
    if kind == "function":
        methods = []
        for d in node.decorator_list:
            if isinstance(d, ast.Call) and d.args and isinstance(d.args[0], (ast.List, ast.Tuple)):
                methods += [e.value.upper() for e in d.args[0].elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
        methods += [m.upper() for m in re.findall(r"request\.method\s*==\s*['\"](\w+)['\"]", body)]
        ids = [a.arg for a in node.args.args[1:] + node.args.kwonlyargs if id_param.search(a.arg)]
        ids += [f"{k} (request data)" for k in re.findall(r"request\.(?:GET|POST|data|query_params)(?:\.get\(|\[)\s*['\"](\w*id|pk)['\"]", body)]
        return sorted(set(methods)) or ["GET"], sorted(set(ids))
    bases = " ".join(ast.unparse(b) for b in node.bases)
    names = {n.name for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    methods = [m.upper() for m in HTTP_METHODS if m in names]
    if names & {"create"} or WRITE_BASE.search(bases):
        methods.append("POST")
    if names & {"update", "partial_update"}:
        methods.append("PUT")
    if "destroy" in names:
        methods.append("DELETE")
    ids = set()
    for n in ast.walk(node):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            ids.update(a.arg for a in n.args.args[1:] + n.args.kwonlyargs if id_param.search(a.arg) and a.arg != "request")
    ids.update(re.findall(r"kwargs(?:\.get\(|\[)\s*['\"](\w+)['\"]", body))
    if DETAIL_BASE.search(bases) or names & {"retrieve", "update", "partial_update", "destroy", "get_object"}:
        ids.add("pk (object lookup)")
    return sorted(set(methods)) or ["GET"], sorted(ids)
