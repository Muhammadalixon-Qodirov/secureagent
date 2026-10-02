"""Deterministic code structure for the v2 sweep (no model involved).

- route_inventory: Flask handlers found by AST — path, methods, decorators, and
  which authorization-related names appear in the body. These are *signals* for
  the model (IDOR reasoning starts from the authorization map), not verdicts.
- chunk_file: split a file into windows of whole top-level definitions
  (<= MAX_WINDOW_LINES each) so a function is never cut in half when possible.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

from .tools import MAX_WINDOW_LINES

ROUTE_DECORATORS = {"route", "get", "post", "put", "patch", "delete"}
AUTH_SIGNALS = re.compile(
    r"current_user|session\b|g\.user|owner|user_id|tenant|org_id|is_member|\brole\b|is_admin|"
    r"abort\(\s*40[13]|login_required|permission|authorize")


@dataclass
class Route:
    file: str
    function: str
    line_start: int
    line_end: int
    path: str | None
    methods: list[str]
    decorators: list[str]
    auth_signals: list[str] = field(default_factory=list)

    def render(self) -> str:
        sig = ", ".join(self.auth_signals) or "none"
        return (f"{self.file}:{self.line_start}-{self.line_end} {','.join(self.methods) or 'GET'} "
                f"{self.path or '?'} -> {self.function}()  decorators=[{', '.join(self.decorators)}]  "
                f"auth-related names in body: {sig}")


def _dec_name(d: ast.expr) -> str:
    target = d.func if isinstance(d, ast.Call) else d
    try:
        return ast.unparse(target)
    except Exception:
        return "?"


def route_inventory(source: str, file: str) -> list[Route]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    lines = source.splitlines()
    routes = []
    for n in ast.walk(tree):
        if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        path, methods, is_route = None, [], False
        for d in n.decorator_list:
            if isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr in ROUTE_DECORATORS:
                is_route = True
                if d.args and isinstance(d.args[0], ast.Constant) and isinstance(d.args[0].value, str):
                    path = d.args[0].value
                if d.func.attr != "route":
                    methods = [d.func.attr.upper()]
                for kw in d.keywords:
                    if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                        methods = [e.value for e in kw.value.elts if isinstance(e, ast.Constant)]
        if not is_route:
            continue
        start = min([d.lineno for d in n.decorator_list] + [n.lineno])
        body = "\n".join(lines[n.lineno - 1:n.end_lineno])
        signals = sorted(set(m.group(0) for m in AUTH_SIGNALS.finditer(body)))
        routes.append(Route(file, n.name, start, n.end_lineno, path, methods,
                            [_dec_name(d) for d in n.decorator_list], signals))
    return sorted(routes, key=lambda r: r.line_start)


def chunk_file(source: str, max_lines: int = MAX_WINDOW_LINES) -> list[tuple[int, int]]:
    """(start, end) line windows built from whole top-level statements."""
    total = len(source.splitlines())
    if total == 0:
        return []
    try:
        tree = ast.parse(source)
        bounds = []
        for node in tree.body:
            start = min([d.lineno for d in getattr(node, "decorator_list", [])] + [node.lineno])
            bounds.append((start, node.end_lineno))
    except SyntaxError:
        bounds = []
    if not bounds:
        return [(s, min(s + max_lines - 1, total)) for s in range(1, total + 1, max_lines)]
    windows, cur_start, cur_end = [], 1, 0
    for s, e in bounds:
        if e - cur_start + 1 <= max_lines:
            cur_end = e
            continue
        if cur_end >= cur_start:
            windows.append((cur_start, cur_end))
        cur_start = cur_end + 1 if cur_end >= cur_start else s
        while e - cur_start + 1 > max_lines:           # one statement longer than a window
            windows.append((cur_start, cur_start + max_lines - 1))
            cur_start += max_lines
        cur_end = e
    windows.append((cur_start, max(cur_end, total)))
    return [(a, min(b, a + max_lines - 1)) for a, b in windows if a <= total]
