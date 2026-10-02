"""Controller-side enforcement of scope. The system prompt describes these rules;
this module is what actually enforces them."""

from __future__ import annotations

import os
from pathlib import Path, PureWindowsPath

from .config import Config


class PolicyViolation(Exception):
    """A requested action is outside the run's authorization. Logged, never executed."""


def check_tool(tool: str, config: Config) -> None:
    if tool not in config.enabled_tools:
        raise PolicyViolation(f"tool {tool!r} is not enabled for this run")


def resolve_in_scope(requested: str, config: Config) -> Path:
    """Map a model-supplied path to a canonical file path inside an authorized root.

    Relative paths are resolved against the first root. The final path is resolved
    (symlinks, '..') and must lie inside a resolved root; comparison uses
    commonpath, so '/srv/app_old' is not accepted for root '/srv/app'.
    """
    if not isinstance(requested, str) or not requested.strip():
        raise PolicyViolation("empty path")
    if "\x00" in requested:
        raise PolicyViolation("NUL byte in path")
    win = PureWindowsPath(requested)
    if win.drive and not Path(requested).is_absolute():
        raise PolicyViolation(f"drive-relative path not allowed: {requested!r}")   # e.g. 'C:secret'

    candidate = Path(requested)
    if not candidate.is_absolute():
        candidate = config.authorized_roots[0] / candidate
    resolved = Path(os.path.realpath(candidate))

    norm = os.path.normcase(str(resolved))      # case-insensitive only where the OS is
    for root in config.authorized_roots:
        root_norm = os.path.normcase(str(root))
        try:
            if os.path.commonpath([norm, root_norm]) == root_norm:
                return resolved
        except ValueError:          # different drives on Windows
            continue
    raise PolicyViolation(f"path outside authorized roots: {requested!r}")


def check_readable(path: Path, config: Config) -> None:
    if not path.is_file():
        raise PolicyViolation(f"not a regular file: {path.name}")
    size = path.stat().st_size
    if size > config.max_file_bytes:
        raise PolicyViolation(f"file larger than max_file_bytes ({size} > {config.max_file_bytes})")
