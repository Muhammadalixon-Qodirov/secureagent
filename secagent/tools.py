"""Controller-executed tools. The model proposes `{tool, arguments}`; only this
module touches the file system or runs scanners.

Every call goes through `ToolRegistry.execute`, which:
  1. checks the tool is enabled for the run (policy),
  2. validates arguments against a strict per-tool model (unknown keys rejected),
  3. resolves every path inside the authorized roots (policy),
  4. runs the tool with size / match / time limits,
  5. assigns an event id and records the call in the trace.
Outcomes are `ok`, `error` (tool or argument problem) or `denied` (policy).
No tool runs a shell; scanners are started with an argument list.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import unicodedata
from pathlib import Path
from typing import Callable, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from . import knowledge
from .config import Config
from .policy import PolicyViolation, check_readable, check_tool, resolve_in_scope
from .trace import Timer, Trace

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules" / "flask-taint.yaml"

MAX_WINDOW_LINES = 120          # SWE-agent found ~100-line windows beat both 30 lines and full files
MAX_LINE_CHARS = 400
MAX_LIST_ENTRIES = 500
MAX_SEARCH_MATCHES = 100
MAX_SCAN_FINDINGS = 100
MAX_KNOWLEDGE_CHARS = 1500
SCAN_TIMEOUT_S = 180
SKIP_DIRS = {".git", ".hg", ".svn", ".venv", "venv", "env", "node_modules", "__pycache__",
             ".mypy_cache", ".pytest_cache", ".tox", "dist", "build", ".idea", ".vscode"}

# zero-width and bidi control characters used to hide instructions in source files
INVISIBLE = {"​", "‌", "‍", "⁠", "﻿",
             "‪", "‫", "‬", "‭", "‮", "⁦", "⁧", "⁨", "⁩"}

BANDIT_FAMILY = {"B608": "sql_injection", "B602": "os_command_injection", "B605": "os_command_injection",
                 "B609": "os_command_injection", "B701": "xss", "B703": "xss", "B704": "xss"}


class ToolError(Exception):
    """The tool could not produce a valid observation (not a policy decision)."""


class ToolResult(BaseModel):
    event_id: str
    tool: str
    status: Literal["ok", "error", "denied"]
    data: dict | None = None
    error: str | None = None
    truncated: bool = False


# ---------------------------------------------------------------- argument models

class _Args(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ListFilesArgs(_Args):
    path: str = "."
    max_entries: int = Field(default=200, ge=1, le=MAX_LIST_ENTRIES)


class ReadFileArgs(_Args):
    path: str
    start_line: int = Field(default=1, ge=1)
    end_line: int | None = Field(default=None, ge=1)


class SearchCodeArgs(_Args):
    pattern: str = Field(min_length=1, max_length=200)
    path: str = "."
    regex: bool = False
    max_matches: int = Field(default=30, ge=1, le=MAX_SEARCH_MATCHES)


class ScanStaticArgs(_Args):
    path: str = "."
    scanner: Literal["semgrep", "bandit", "all"] = "semgrep"


class RetrieveKnowledgeArgs(_Args):
    query: str = Field(min_length=1, max_length=300)
    cwe: str | None = Field(default=None, pattern=r"^CWE-\d+$")
    k: int = Field(default=4, ge=1, le=8)


# ---------------------------------------------------------------- helpers

def _sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _is_binary(raw: bytes) -> bool:
    return b"\x00" in raw[:4096]


def _invisible_chars(text: str) -> list[str]:
    return sorted({f"U+{ord(c):04X} {unicodedata.name(c, '?')}" for c in text if c in INVISIBLE})


def _find_exe(name: str) -> str:
    exe = shutil.which(name, path=str(Path(sys.executable).parent)) or shutil.which(name)
    if not exe:
        raise ToolError(f"{name} is not installed")
    return exe


class ToolRegistry:
    def __init__(self, config: Config, trace: Trace, knowledge_db: Path | None = None):
        self.config = config
        self.trace = trace
        self.knowledge_db = knowledge_db or knowledge.DEFAULT_DB
        self.results: dict[str, ToolResult] = {}      # full results, for evidence validation
        self._tools: dict[str, tuple[type[_Args], Callable]] = {
            "list_files": (ListFilesArgs, self._list_files),
            "read_file": (ReadFileArgs, self._read_file),
            "search_code": (SearchCodeArgs, self._search_code),
            "scan_static": (ScanStaticArgs, self._scan_static),
            "retrieve_knowledge": (RetrieveKnowledgeArgs, self._retrieve_knowledge),
        }

    # -------------------------------------------------------------- dispatch

    def execute(self, tool: str, arguments: dict) -> ToolResult:
        event_id = self.trace.next_event_id()
        data, error, status, truncated, args_log = None, None, "ok", False, arguments
        with Timer() as t:
            try:
                check_tool(tool, self.config)
                if tool not in self._tools:
                    raise ToolError(f"tool {tool!r} is enabled but not implemented")
                model, fn = self._tools[tool]
                args = model.model_validate(arguments if isinstance(arguments, dict) else {})
                args_log = args.model_dump()
                data, truncated = fn(args)
            except PolicyViolation as exc:
                status, error = "denied", str(exc)
            except ValidationError as exc:
                status, error = "error", "invalid arguments: " + "; ".join(
                    f"{'.'.join(map(str, e['loc'])) or 'arguments'}: {e['msg']}" for e in exc.errors())
            except ToolError as exc:
                status, error = "error", str(exc)
            except Exception as exc:                  # never let a tool crash the run
                status, error = "error", f"unexpected {type(exc).__name__}: {exc}"
        result = ToolResult(event_id=event_id, tool=tool, status=status, data=data, error=error, truncated=truncated)
        self.results[event_id] = result
        self.trace.record({
            "event_id": event_id, "tool": tool, "arguments": args_log, "status": status,
            "duration_ms": t.ms, "truncated": truncated, "error": error,
            "result_sha256": _sha256(json.dumps(data, sort_keys=True, ensure_ascii=False).encode()) if data else None,
            "summary": self._summary(tool, data),
        })
        return result

    @staticmethod
    def _summary(tool: str, data: dict | None) -> dict | None:
        if not data:
            return None
        if tool == "read_file":
            return {k: data[k] for k in ("path", "start_line", "end_line", "total_lines", "file_sha256", "flags")}
        if tool in ("search_code", "scan_static", "list_files", "retrieve_knowledge"):
            key = {"search_code": "matches", "scan_static": "findings", "list_files": "files",
                   "retrieve_knowledge": "results"}[tool]
            return {"count": len(data.get(key, []))}
        return None

    def _root_of(self, p: Path) -> Path:
        nc = os.path.normcase
        for root in self.config.authorized_roots:
            try:
                if nc(os.path.commonpath([str(p), str(root)])) == nc(str(root)):
                    return root
            except ValueError:          # different drives on Windows
                continue
        raise PolicyViolation(f"path outside authorized roots: {p}")

    def _rel(self, p: Path) -> str:
        root = self._root_of(p)
        return Path(os.path.relpath(p, root)).as_posix()

    def _iter_files(self, base: Path):
        if base.is_file():
            yield base
            return
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            for f in sorted(filenames):
                p = Path(dirpath) / f
                try:
                    resolve_in_scope(str(p), self.config)       # skips symlinks that leave the root
                except PolicyViolation:
                    continue
                yield p

    # -------------------------------------------------------------- tools

    def _list_files(self, a: ListFilesArgs):
        base = resolve_in_scope(a.path, self.config)
        if not base.exists():
            raise ToolError(f"no such path: {a.path}")
        files = []
        for p in self._iter_files(base):
            if len(files) >= a.max_entries:
                return {"files": files}, True
            files.append({"path": self._rel(p), "bytes": p.stat().st_size})
        return {"files": files}, False

    def _read_file(self, a: ReadFileArgs):
        path = resolve_in_scope(a.path, self.config)
        check_readable(path, self.config)
        raw = path.read_bytes()
        if _is_binary(raw):
            raise ToolError("binary file")
        text = raw.decode("utf-8", errors="replace")
        all_lines = text.splitlines()
        total = len(all_lines)
        if a.start_line > max(total, 1):
            raise ToolError(f"start_line {a.start_line} beyond end of file ({total} lines)")
        requested_end = a.end_line or a.start_line + MAX_WINDOW_LINES - 1
        if requested_end < a.start_line:
            raise ToolError("end_line must be >= start_line")
        end = min(requested_end, a.start_line + MAX_WINDOW_LINES - 1, total)
        truncated = end < min(requested_end, total)
        lines, long_lines = [], 0
        for n in range(a.start_line, end + 1):
            s = all_lines[n - 1]
            if len(s) > MAX_LINE_CHARS:
                s, long_lines = s[:MAX_LINE_CHARS] + " …[line truncated]", long_lines + 1
            lines.append({"n": n, "text": s})
        flags = []
        hidden = _invisible_chars("\n".join(x["text"] for x in lines))
        if hidden:
            flags.append("invisible_unicode: " + ", ".join(hidden))
        if long_lines:
            flags.append(f"long_lines_truncated: {long_lines}")
        return {"path": self._rel(path), "start_line": a.start_line, "end_line": end, "total_lines": total,
                "file_sha256": _sha256(raw), "lines": lines, "flags": flags}, truncated or bool(long_lines)

    def _search_code(self, a: SearchCodeArgs):
        base = resolve_in_scope(a.path, self.config)
        if not base.exists():
            raise ToolError(f"no such path: {a.path}")
        if a.regex:
            try:
                rx = re.compile(a.pattern)
            except re.error as exc:
                raise ToolError(f"invalid regex: {exc}") from exc
            match = rx.search
        else:
            match = lambda s, p=a.pattern: p in s   # noqa: E731
        matches, files_scanned = [], 0
        for p in self._iter_files(base):
            try:
                if p.stat().st_size > self.config.max_file_bytes:
                    continue
                raw = p.read_bytes()
            except OSError:
                continue
            if _is_binary(raw):
                continue
            files_scanned += 1
            for n, line in enumerate(raw.decode("utf-8", errors="replace").splitlines(), 1):
                if match(line[:2000]):
                    matches.append({"path": self._rel(p), "line": n, "text": line.strip()[:MAX_LINE_CHARS]})
                    if len(matches) >= a.max_matches:
                        return {"matches": matches, "files_scanned": files_scanned}, True
        return {"matches": matches, "files_scanned": files_scanned}, False

    def _scan_static(self, a: ScanStaticArgs):
        target = resolve_in_scope(a.path, self.config)
        root = self._root_of(target)
        rel_target = os.path.relpath(target, root)
        findings, meta = [], {}
        if a.scanner in ("semgrep", "all"):
            f, meta["semgrep"] = self._run_semgrep(root, rel_target)
            findings += f
        if a.scanner in ("bandit", "all"):
            f, meta["bandit"] = self._run_bandit(root, rel_target)
            findings += f
        findings.sort(key=lambda x: (x["file"], x["line_start"], x["scanner"]))
        truncated = len(findings) > MAX_SCAN_FINDINGS
        return {"findings": findings[:MAX_SCAN_FINDINGS], "scanners": meta,
                "note": "scanner hits are hypotheses, not confirmed vulnerabilities"}, truncated

    def _run(self, cmd: list[str], cwd: Path) -> subprocess.CompletedProcess:
        # subprocess.run(timeout=...) kills only the direct child; semgrep's worker
        # (semgrep-core) kept running and holding the pipes (a 180 s timeout took 425 s).
        # Start a new process group and kill the whole tree on timeout.
        posix = os.name != "nt"
        proc = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                encoding="utf-8", errors="replace", shell=False, start_new_session=posix,
                                creationflags=0 if posix else subprocess.CREATE_NEW_PROCESS_GROUP)
        try:
            out, err = proc.communicate(timeout=SCAN_TIMEOUT_S)
        except subprocess.TimeoutExpired as exc:
            if posix:
                os.killpg(proc.pid, 9)
            else:
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True)
            proc.communicate()
            raise ToolError(f"{Path(cmd[0]).stem} timed out after {SCAN_TIMEOUT_S}s") from exc
        return subprocess.CompletedProcess(cmd, proc.returncode, out, err)

    def _run_semgrep(self, root: Path, rel_target: str):
        exe = _find_exe("semgrep")
        # --project-root: otherwise semgrep treats the enclosing git repository as the project
        # root; when the target sits inside a very large repo (here: the whole home directory)
        # target discovery hangs for minutes. The authorized root is the project.
        cmd = [exe, "scan", "--config", str(RULES), "--json", "--metrics=off", "--disable-version-check",
               "--quiet", "--timeout", "30", "--project-root", str(root), rel_target]
        for d in sorted(SKIP_DIRS):     # vendored virtualenvs etc. (one RealVuln target ships 3 000 venv files)
            cmd[-1:-1] = ["--exclude", d]
        proc = self._run(cmd, root)
        try:
            out = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise ToolError(f"semgrep produced no JSON (exit {proc.returncode}): {proc.stderr.strip()[:300]}") from exc
        findings = []
        for r in out.get("results", []):
            md = r.get("extra", {}).get("metadata", {})
            findings.append({
                "scanner": "semgrep", "rule_id": r["check_id"].split(".")[-1],
                "family": md.get("family"), "cwe": md.get("cwe", []),
                "file": Path(r["path"]).as_posix(), "line_start": r["start"]["line"], "line_end": r["end"]["line"],
                "severity": r.get("extra", {}).get("severity"), "message": r.get("extra", {}).get("message", "").strip(),
            })
        errors = [e.get("message", "")[:200] for e in out.get("errors", [])]
        return findings, {"version": out.get("version"), "rules": RULES.name, "errors": errors[:5],
                          "partial": bool(errors)}

    def _run_bandit(self, root: Path, rel_target: str):
        exe = _find_exe("bandit")
        proc = self._run([exe, "-r", rel_target, "-f", "json", "-q"], root)
        try:
            out = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise ToolError(f"bandit produced no JSON (exit {proc.returncode}): {proc.stderr.strip()[:300]}") from exc
        findings = []
        for r in out.get("results", []):
            cwe = r.get("issue_cwe", {}).get("id")
            lr = r.get("line_range") or [r["line_number"]]
            findings.append({
                "scanner": "bandit", "rule_id": r["test_id"], "family": BANDIT_FAMILY.get(r["test_id"]),
                "cwe": [f"CWE-{cwe}"] if cwe else [], "file": Path(r["filename"]).as_posix(),
                "line_start": min(lr), "line_end": max(lr),
                "severity": r.get("issue_severity"), "message": r.get("issue_text", ""),
            })
        errors = [str(e)[:200] for e in out.get("errors", [])]
        return findings, {"errors": errors[:5], "partial": bool(errors)}

    def _retrieve_knowledge(self, a: RetrieveKnowledgeArgs):
        try:
            rows = knowledge.search(a.query, a.k, a.cwe, self.knowledge_db)
        except FileNotFoundError as exc:
            raise ToolError(str(exc)) from exc
        results, truncated = [], False
        for r in rows:
            text = r["text"]
            if len(text) > MAX_KNOWLEDGE_CHARS:
                text, truncated = text[:MAX_KNOWLEDGE_CHARS] + " …", True
            results.append({"id": r["id"], "title": r["title"], "text": text, "cwe_ids": r["cwe_ids"].split(),
                            "source_url": r["source_url"], "version": r["version"], "license": r["license"]})
        return {"results": results}, truncated
