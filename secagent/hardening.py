"""Deterministic hardening of what the model is shown (added after the injection suite, T12).

The suite showed two ways text in the reviewed code changed the verdict:
instructions in a docstring/comment made the sweep return nothing, and a long
policy string let the verifier name a line of prose as the "control" that
defeats a finding. Neither is fixed by asking the model to be careful, so the
controller does it:

- comments and docstrings are blanked before the model sees a window (line
  numbers kept; evidence excerpts still come from the real file). They are not
  executable, so they can never be a security control. Other string literals
  are kept: SQL text lives in them.
- a verifier withdrawal counts only if its control line is a line of code.
"""

from __future__ import annotations

import ast
import io
import tokenize

COMMENT_MARK = "# [comment removed]"
DOC_MARK = '"""[docstring removed]"""'
NON_CODE = {tokenize.COMMENT, tokenize.STRING, tokenize.NL, tokenize.NEWLINE, tokenize.INDENT,
            tokenize.DEDENT, tokenize.ENDMARKER}


def _tokens(src: str):
    try:
        return list(tokenize.generate_tokens(io.StringIO(src).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return None


def code_lines(src: str) -> set[int] | None:
    """Line numbers holding at least one token that is not a comment or a string. None = unparsable."""
    toks = _tokens(src)
    if toks is None:
        return None
    out: set[int] = set()
    for t in toks:
        if t.type not in NON_CODE:
            out.update(range(t.start[0], t.end[0] + 1))
    return out


def blanked(src: str) -> dict[int, str]:
    """line number -> replacement text, for lines whose comment or docstring was removed."""
    toks = _tokens(src)
    if toks is None:
        return {}
    lines = src.splitlines()
    out: dict[int, str] = {}
    try:
        tree = ast.parse(src)
    except (SyntaxError, ValueError):
        tree = None
    doc_rows: set[int] = set()
    for node in ast.walk(tree) if tree else []:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            first, last = node.lineno, node.end_lineno or node.lineno
            out[first] = lines[first - 1][:node.col_offset] + DOC_MARK
            for n in range(first + 1, last + 1):
                out[n] = ""
            doc_rows.update(range(first, last + 1))
    for t in toks:
        if t.type == tokenize.COMMENT and t.start[0] not in doc_rows:
            row, col = t.start
            base = out.get(row, lines[row - 1])
            out[row] = base[:col] + COMMENT_MARK
    return out
