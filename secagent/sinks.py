"""v5: deterministic injection-sink scan (no model, no framework knowledge).

T13 (Django): the model sweep read the right files and still returned empty lists
for `BASE_DIR / request.GET["ref"]` followed by read_text(), for a request body
written to a caller-named file and for a request-supplied Mongo filter. The
authorization seeds of v3 showed that the verifier judges one concrete claim far
better than the sweep finds it. This module does the same for the injection
families: it finds the *operation* (a query built from text, a file opened by a
computed path) with the AST, follows the value back inside the function, and
hands the verifier one claim per sink.

Sinks are Python-level (DB-API `execute`, `open`, `pathlib`), sources are
recognised by generic words (request, query, param, body, ...), so nothing here
depends on the web framework.

A seed is made when the value at the sink
  - comes from something request-like in the same function (priority 0), or
  - comes from a parameter of the function and, for file sinks, some caller in the
    project passes it a request-like value (priority 1). SQL text built from a
    parameter is seeded without looking at callers: building SQL from values is
    the defect whoever calls it.
Values built only from constants, configuration or the environment are not seeded.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

SQL_METHODS = {"execute", "executemany", "executescript", "raw", "extra", "execute_sql", "fetch", "fetchrow",
               "fetchval", "fetch_all", "fetch_one", "query"}
SQL_WRAPPERS = {"text", "SQL", "RawSQL", "TextClause"}
SQL_WORDS = re.compile(r"\b(select|insert\s+into|update|delete\s+from|where|order\s+by|union|like)\b|"
                       r"\w+\s*=\s*'?\s*$|=\s*'?\s*%s|=\s*'?\{", re.I)
NOSQL_METHODS = {"find", "find_one", "find_one_and_update", "find_one_and_delete", "delete_one", "delete_many",
                 "update_one", "update_many", "count_documents", "aggregate"}
NOSQL_HINT = re.compile(r"mongo|pymongo|motor|collection|\.db\b|bson", re.I)
FILE_FUNCS = {"open", "file", "send_file", "FileResponse", "remove", "unlink", "rmtree", "copyfile", "copy", "move", "listdir",
              "StreamingResponse", "static_file"}
PATH_METHODS = {"read_text", "read_bytes", "write_text", "write_bytes", "open", "unlink", "save", "iterdir"}
SOURCE_WORDS = re.compile(r"request|\breq\b|query|param|\bargs?\b|argument|form|body|cookie|header|environ|payload|"
                          r"\bjson\b|\bPOST\b|\bGET\b|\bFILES\b|\binput\b|match_info|\burl\b|\buri\b", re.I)
NOT_SOURCE = re.compile(r"os\.environ|getenv|settings\.|config\.|app\.config|__file__")
PATH_CONTROLS = re.compile(r"secure_filename|safe_join|send_from_directory|commonpath|is_relative_to|\.relative_to\(|"
                           r"realpath|abspath|\.resolve\(\)|basename|\.startswith\(|\.isalnum\(\)|re\.(?:full)?match|"
                           r"\.\.[\"'] in|not in \w*(?:ALLOWED|allowed)")
SQL_CONTROLS = re.compile(r"\bint\(|\bfloat\(|\.isdigit\(\)|\.isalnum\(\)|\bin\s+\(?\[?[\"'A-Z_]|ALLOWED|allowed|whitelist|"
                          r"re\.(?:full)?match|quote_ident|sql\.Identifier")
# the result of a lookup is stored data, not the request value that selected it
DB_LOOKUP = re.compile(r"\.(?:query|filter|filter_by|execute|scalar|scalars|first|one|one_or_none|fetchone|fetchall|"
                       r"fetchrow|find_one|get_or_404|first_or_404)\(|\.objects\.|get_object_or_404\(|select\(|"
                       r"(?:db|session|conn|cursor|cur)\.\w+\(")
NOT_PARAMS = {"self", "cls", "args", "kwargs", "options", "db", "session", "conn", "cursor"}
PATH_PARTS = {"name", "stem", "suffix", "id", "pk"}
SANITIZERS = {"secure_filename", "basename", "int", "float", "bool", "len", "uuid4", "token_hex", "token_urlsafe",
              "hexdigest", "safe_join", "quote_ident", "isoformat", "strftime", "slugify"}
PROPAGATORS = {"join", "joinpath", "Path", "PurePath", "PosixPath", "str", "bytes", "format", "strip", "lstrip",
               "rstrip", "lower", "upper", "replace", "unquote", "unquote_plus", "loads", "decode", "encode", "get",
               "pop", "split", "rsplit", "abspath", "normpath", "realpath", "resolve", "dirname", "expanduser",
               "dict", "list", "tuple", "getattr", "b64decode", "urlparse", "parse_qs", "read", "items", "values",
               "keys", "title", "capitalize", "with_suffix", "with_name", "relpath", "fspath", "copy", "setdefault"}
HTTP_VERBS = {"get", "post", "put", "patch", "delete", "head", "do_GET", "do_POST", "do_PUT", "do_DELETE"}
NON_REQUEST_FILE = re.compile(r"/(management/commands|migrations|scripts?|fixtures|seeds?)/|/(seed\w*|populate\w*|"
                              r"manage|setup|conftest|settings\w*|config\w*|wsgi|asgi)\.py$")
FILE_PARAM = re.compile(r"file_?name|\bfname\b|\bfile_?path\b|^path$|^file$", re.I)
MAX_SEEDS = 60
# ---- v6: how strong is the control in front of the sink (docs/V6_REJA.md, step 4)
# Real fixes (CVE-replay dev half) replace a weak containment check by a strong one, or add a strong one;
# v5 flagged both versions alike. Strong: the path is resolved and compared structurally, or reduced to a
# single component. Weak: a text test on the path string that prefix confusion or encoding gets around.
STRONG_PATH = re.compile(r"commonpath\(|\.is_relative_to\(|\.relative_to\(|secure_filename\(|safe_join\(|"
                         r"send_from_directory\(|os\.path\.basename\(|\bbasename\(|"
                         r"\.resolve\(\)\.parent\s*[!=]=|\.startswith\([^)\n]*(?:os\.sep|sep\b|[\"']/[\"'])")
WEAK_PATH = re.compile(r"\.startswith\(|[\"']\.\.[\"']\s+(?:not\s+)?in\b|\.replace\(\s*[\"']\.\.|normpath\(|"
                       r"\.lstrip\(\s*[\"'][./\\]+[\"']")
STRONG_SQL = re.compile(r"sql\.Identifier\(|sql\.Literal\(|sql\.Placeholder\(|quote_ident\(|quote_name\(|"
                        r"\.isidentifier\(\)|bindparam\(|sqlalchemy\.sql\.expression")
SAME_BUG_LINES = 15                 # sinks of one family this close together in one function are one seed


@dataclass
class SinkSeed:
    file: str
    line: int
    family: str                     # sql_injection | path_traversal
    title: str
    reason: str
    func: str
    func_start: int
    func_end: int
    priority: int                   # 0 = request-like source in the function, 1 = reaches the sink through a parameter
    controls: list[str]
    control: str = ""               # v6: "" none seen, "weak: <text>" a bypassable check stands before the sink


def _name(n: ast.AST) -> str:
    if isinstance(n, ast.Attribute):
        return n.attr
    if isinstance(n, ast.Name):
        return n.id
    return ""


def _names(n: ast.AST) -> set[str]:
    return {x.id for x in ast.walk(n) if isinstance(x, ast.Name)}


def _built(n: ast.AST) -> ast.AST | None:
    """The dynamic part of a string built from pieces (f-string, %, +, .format), else None."""
    if isinstance(n, ast.JoinedStr) and any(isinstance(v, ast.FormattedValue) for v in n.values):
        return n
    if isinstance(n, ast.BinOp) and isinstance(n.op, (ast.Mod, ast.Add)):
        if isinstance(n.op, ast.Mod) and isinstance(n.left, ast.Constant) and isinstance(n.left.value, str):
            return n.right
        if isinstance(n.op, ast.Add):
            return n
    if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "format"
            and (n.args or n.keywords)):
        return n
    return None


def _static_text(n: ast.AST) -> str:
    return " ".join(c.value for c in ast.walk(n) if isinstance(c, ast.Constant) and isinstance(c.value, str))


class _Func:
    """Value flow inside one function. origin(expr) is 0 when the value is request-like, 1 when it comes
    from a parameter, None when it is neither (constants, configuration, stored data, sanitised values)."""

    def __init__(self, fn: ast.AST, lines: list[str], in_class: bool = False):
        self.fn = fn
        args = fn.args
        self.params = {a.arg for a in args.posonlyargs + args.args + args.kwonlyargs} - NOT_PARAMS
        self.text = "\n".join(lines[fn.lineno - 1:fn.end_lineno])
        self.assign: dict[str, list[ast.AST]] = {}
        for n in ast.walk(fn):
            targets, value = [], None
            if isinstance(n, ast.Assign):
                targets, value = n.targets, n.value
            elif isinstance(n, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)) and n.value is not None:
                targets, value = [n.target], n.value
            elif isinstance(n, (ast.For, ast.AsyncFor, ast.comprehension)):
                targets, value = [n.target], n.iter
            elif isinstance(n, ast.withitem) and n.optional_vars is not None:
                targets, value = [n.optional_vars], n.context_expr
            for t in targets:
                for name in _names(t):
                    self.assign.setdefault(name, []).append(value)
        self.req = {p for p in self.params if SOURCE_WORDS.search(p)}
        # an entry point's parameters are the request: a function registered under a URL path by a
        # decorator ("/items/{id}"), or an HTTP-verb method of a class (get, post, do_GET, ...)
        routed = any(isinstance(d, ast.Call) and any(isinstance(a, ast.Constant) and isinstance(a.value, str)
                                                     and a.value.startswith("/") for a in d.args)
                     for d in fn.decorator_list)
        if routed or (in_class and fn.name in HTTP_VERBS):
            self.req = set(self.params)
        self.par = set(self.params) - self.req
        for _ in range(4):
            for name, values in self.assign.items():
                if name in self.params:
                    continue
                kinds = [k for k in (self.origin(v) for v in values) if k is not None]
                if kinds and min(kinds) == 0:
                    self.req.add(name)
                elif kinds:
                    self.par.add(name)

    def origin(self, n: ast.AST) -> int | None:
        if isinstance(n, ast.Name):
            return 0 if n.id in self.req else 1 if n.id in self.par else None
        if isinstance(n, ast.Constant) or n is None:
            return None
        if isinstance(n, ast.Await):
            return self.origin(n.value)
        if isinstance(n, ast.Attribute):
            if n.attr in PATH_PARTS:                        # Path(x).name: a single path component
                return None
            txt = ast.unparse(n)
            if NOT_SOURCE.search(txt):
                return None
            if SOURCE_WORDS.search(txt):
                return 0
            return self.origin(n.value)
        if isinstance(n, ast.Subscript):
            return self.origin(n.value)
        if isinstance(n, ast.Call):
            name, callee = _name(n.func), ast.unparse(n.func)
            if name in SANITIZERS or NOT_SOURCE.search(callee) or DB_LOOKUP.search(callee + "("):
                return None
            if SOURCE_WORDS.search(callee):
                return 0
            if name not in PROPAGATORS:                     # an unknown function returns its own data
                return None
            parts = list(n.args) + [k.value for k in n.keywords]
            if isinstance(n.func, ast.Attribute):
                parts.append(n.func.value)
            return self._min(parts)
        if isinstance(n, ast.Starred):
            return self.origin(n.value)
        return self._min(list(ast.iter_child_nodes(n)))

    def _min(self, nodes) -> int | None:
        kinds = [k for k in (self.origin(x) for x in nodes) if k is not None]
        return min(kinds) if kinds else None

    def names(self, n: ast.AST, kind: int) -> list[str]:
        pool = self.req if kind == 0 else self.par
        return sorted(_names(n) & pool) or [ast.unparse(n)[:40]]

    def resolve(self, n: ast.AST) -> ast.AST:
        """A bare name used at the sink -> the expression last assigned to it (one step)."""
        if isinstance(n, ast.Name) and n.id in self.assign and n.id not in self.params:
            built = [v for v in self.assign[n.id] if _built(v) is not None]
            return built[-1] if built else self.assign[n.id][-1]
        return n


def _functions(tree: ast.AST):
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield n


def _own_calls(fn: ast.AST):
    """Calls in fn's own body, not in functions nested inside it."""
    stack = list(ast.iter_child_nodes(fn))
    while stack:
        n = stack.pop()
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(n, ast.Call):
            yield n
        stack.extend(ast.iter_child_nodes(n))


def _sql_sink(call: ast.Call, f: _Func, file_text: str):
    name = _name(call.func)
    if (isinstance(call.func, ast.Attribute) and name in SQL_METHODS or name in SQL_WRAPPERS) and call.args:
        arg = call.args[0]
        if isinstance(arg, ast.Call) and _name(arg.func) in SQL_WRAPPERS and arg.args:
            if name not in SQL_WRAPPERS:
                return None                         # execute(text(...)): the text() call is the sink
            arg = arg.args[0]
        arg = f.resolve(arg)
        dyn = _built(arg)
        if dyn is not None and SQL_WORDS.search(_static_text(arg)):
            return "SQL text built from values", dyn
    if (isinstance(call.func, ast.Attribute) and name in NOSQL_METHODS and call.args
            and NOSQL_HINT.search(file_text) and not isinstance(call.args[0], (ast.Dict, ast.Constant))):
        return "query filter object supplied by the caller (NoSQL injection)", call.args[0]
    return None


def _file_sink(call: ast.Call, f: _Func):
    name = _name(call.func)
    if isinstance(call.func, ast.Attribute) and name in PATH_METHODS and name != "save":
        recv = call.func.value                      # (BASE / name).read_text(), target.write_bytes(...)
        if name == "open" and not _pathish(recv, f):
            return None
        return f"file operation .{name}() on a computed path", f.resolve(recv)
    if (isinstance(call.func, ast.Attribute) and name == "save" and call.args
            and not isinstance(call.args[0], ast.Starred)):
        return "upload saved under a computed path", f.resolve(call.args[0])
    if name in FILE_FUNCS and call.args:
        if isinstance(call.func, ast.Attribute) and _name(call.func.value) not in ("os", "shutil", "io", "codecs", "path"):
            return None
        return f"{name}() on a computed path", f.resolve(call.args[0])
    return None


def _pathish(n: ast.AST, f: _Func) -> bool:
    n = f.resolve(n)
    return (isinstance(n, ast.BinOp) and isinstance(n.op, ast.Div)) or "Path(" in ast.unparse(n) or "path" in ast.unparse(n).lower()


def _constant_path(n: ast.AST) -> bool:
    return isinstance(n, ast.Constant) or not _names(n)


def _guards(funcs: dict) -> set[str]:
    """v6: project functions that are themselves a strong path check (return or raise on containment)."""
    return {f.fn.name for f in funcs.values()
            if STRONG_PATH.search(f.text) and re.search(r"\breturn\b|\braise\b", f.text)
            and not any(True for c in _own_calls(f.fn) if _name(c.func) in ("open", "read_text", "write_text",
                                                                              "read_bytes", "write_bytes"))}


def _control(f: "_Func", line: int, family: str, guards: set[str]) -> tuple[str, str]:
    """(strength, text) of the control standing before `line` in f: strong / weak / ''."""
    before = "\n".join(f.text.splitlines()[:max(line - f.fn.lineno, 0) + 1])
    if family == "sql_injection":
        m = STRONG_SQL.search(f.text)
        return ("strong", m.group(0)) if m else ("", "")
    m = STRONG_PATH.search(before)
    if m:
        return "strong", m.group(0)
    called = sorted({_name(c.func) for c in _own_calls(f.fn) if c.lineno <= line} & guards)
    if called:
        return "strong", called[0] + "()"
    m = WEAK_PATH.search(before)
    return ("weak", m.group(0)) if m else ("", "")


def scan(files: dict[str, str], v6: bool = False, protected: list | None = None) -> list[SinkSeed]:
    """files: relative path -> source. Seeds sorted by priority, capped at MAX_SEEDS.
    v6=True: a sink behind a strong control is not seeded (it is appended to `protected` with the control
    for the report); one behind a weak control is seeded as bypassable."""
    trees = {}
    for rel, src in files.items():
        try:
            trees[rel] = ast.parse(src)
        except (SyntaxError, ValueError):
            continue
    funcs: dict[tuple[str, int], _Func] = {}
    for rel, tree in trees.items():
        lines = files[rel].splitlines()
        methods = {id(m) for c in ast.walk(tree) if isinstance(c, ast.ClassDef) for m in c.body}
        for fn in _functions(tree):
            funcs[(rel, fn.lineno)] = _Func(fn, lines, id(fn) in methods)
        top = [st for st in tree.body if not isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
        if top:
            mod = ast.FunctionDef(name="<module>", args=ast.arguments(posonlyargs=[], args=[], kwonlyargs=[],
                                  kw_defaults=[], defaults=[]), body=top, decorator_list=[],
                                  lineno=1, end_lineno=len(lines) or 1)
            funcs[(rel, 0)] = _Func(mod, lines)
    # which function names are called with a request-like argument somewhere in the project
    fed: set[str] = set()
    for f in funcs.values():
        for call in _own_calls(f.fn):
            if any(f.origin(a) == 0 for a in list(call.args) + [k.value for k in call.keywords]):
                fed.add(_name(call.func))

    guards = _guards(funcs) if v6 else set()
    seeds: list[SinkSeed] = []
    for (rel, _), f in funcs.items():
        if NON_REQUEST_FILE.search("/" + rel):
            continue
        for call in _own_calls(f.fn):
            hit, family = _sql_sink(call, f, files[rel]), "sql_injection"
            if hit is None:
                hit, family = _file_sink(call, f), "path_traversal"
            if hit is None:
                continue
            what, dyn = hit
            if family == "path_traversal" and _constant_path(dyn):
                continue
            prio = f.origin(dyn)
            if prio is None:
                continue
            names = f.names(dyn, prio)
            if (prio == 1 and family == "path_traversal" and f.fn.name not in fed
                    and not any(FILE_PARAM.search(x) for x in f.names(dyn, 1))):
                continue
            controls = sorted(set(m.group(0) for m in (PATH_CONTROLS if family == "path_traversal" else SQL_CONTROLS)
                                  .finditer(f.text)))[:4]
            src = ("a request-like value" if prio == 0 else "a parameter of this function") + f" ({', '.join(names)[:80]})"
            strength, ctext = _control(f, call.lineno, family, guards) if v6 else ("", "")
            if strength == "strong":
                if protected is not None:
                    protected.append((rel, call.lineno, family, f.fn.name, ctext))
                continue
            title = ("NoSQL injection (query filter taken from the request) in " if "NoSQL" in what
                     else "SQL injection in " if family == "sql_injection"
                     else "Path traversal (containment check can be bypassed) in " if strength == "weak"
                     else "Path traversal in ") + f.fn.name
            reason = (f"{what}; the value comes from {src}; " +
                      (f"the only check before it is a text test on the path ({ctext.strip()}), which prefix "
                       f"confusion or an encoded separator gets around" if strength == "weak"
                       else "no parameter binding / containment recognised by the scan"))
            seeds.append(SinkSeed(rel, call.lineno, family, title, reason, f.fn.name, f.fn.lineno,
                                  f.fn.end_lineno or f.fn.lineno, prio, controls,
                                  f"weak: {ctext.strip()}" if strength == "weak" else ""))
    seeds.sort(key=lambda s: (s.priority, s.file, s.line))
    out = []
    for s in seeds:                                 # nearby sinks of one family in one function: one seed
        if not any(o.file == s.file and o.family == s.family and o.func_start == s.func_start
                   and abs(o.line - s.line) < SAME_BUG_LINES for o in out):
            out.append(s)
    return out[:MAX_SEEDS]


def render(s: SinkSeed) -> str:
    return (f"SINK FACTS (from AST, trusted): {s.family} sink at line {s.line} in {s.func} "
            f"(lines {s.func_start}-{s.func_end}); {s.reason}"
            + (f"; names in this function that may be controls: {', '.join(s.controls)}" if s.controls else ""))
