"""Learned false-positive filter: a small logistic regression over candidate findings.

The alternative to the LLM verifier (one model call per candidate): features read
deterministically from the finding and the code around its evidence line, weights
learned from labelled dev runs. Design fixed before the first fit, with no search:
the features below, L2 = 1.0, 400 epochs of full-batch gradient descent, threshold 0.5.
No sklearn dependency; the data is tens of rows.
"""

from __future__ import annotations

import json
import math
import re
from pathlib import Path

L2 = 1.0
EPOCHS = 400
LR = 0.1
THRESHOLD = 0.5
NEAR = 15

SQL_SINK = re.compile(r"\.execute\(|\.raw\(|text\(|executescript\(|cursor\.", re.I)
SQL_FORMAT = re.compile(r"""f["'].*(SELECT|INSERT|UPDATE|DELETE|WHERE)|\.format\(|["']\s*%\s*[\w(]|["']\s*\+\s*\w""", re.I)
SQL_PARAM = re.compile(r"""["'][^"']*(\?|%s|:\w+)[^"']*["']\s*,\s*[\[(\w{]""")
PATH_SINK = re.compile(r"\bopen\(|send_file\(|os\.path\.join\(|Path\(|os\.remove\(|shutil\.")
PATH_SAFE = re.compile(r"send_from_directory|secure_filename|safe_join|realpath|abspath|commonpath|is_relative_to")
OBJ_LOOKUP = re.compile(r"query\.get|get_or_404|filter_by|\.filter\(|WHERE\s+\w*id\s*=|\.get\(\s*\w*id", re.I)
OWNER_REF = re.compile(r"current_user|session\[|session\.get|g\.user|owner|user_id\s*[!=]=")
REQUEST = re.compile(r"request\.|Depends\(|\bargs\.get|\bform\[|json\[")

FEATURES = ["bias", "fam_sqli", "fam_path", "fam_idor", "authz_seed", "in_route", "sql_sink", "sql_format",
            "sql_param", "path_sink", "path_safe_near", "obj_lookup", "owner_near", "request_near", "file_load"]


def features(f: dict, root: Path, file_counts: dict[str, int]) -> list[float]:
    ev = f["evidence"][0]
    try:
        lines = (root / ev["file"]).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        lines = []
    line = ev.get("excerpt") or (lines[ev["line_start"] - 1] if 0 < ev["line_start"] <= len(lines) else "")
    near = "\n".join(lines[max(0, ev["line_start"] - NEAR - 1):ev["line_end"] + NEAR])
    cwe = f.get("cwe_id")
    v = {
        "bias": 1.0,
        "fam_sqli": cwe == "CWE-89", "fam_path": cwe == "CWE-22", "fam_idor": cwe == "CWE-639",
        "authz_seed": f.get("confidence_rationale", "").startswith("authz analysis"),
        "in_route": not re.fullmatch(r"[\w./-]+:\d+", f.get("entrypoint", "")),
        "sql_sink": bool(SQL_SINK.search(line)), "sql_format": bool(SQL_FORMAT.search(line)),
        "sql_param": bool(SQL_PARAM.search(line)), "path_sink": bool(PATH_SINK.search(line)),
        "path_safe_near": bool(PATH_SAFE.search(near)), "obj_lookup": bool(OBJ_LOOKUP.search(near)),
        "owner_near": bool(OWNER_REF.search(near)), "request_near": bool(REQUEST.search(near)),
        "file_load": math.log1p(file_counts.get(ev["file"], 0)) / 3,      # many candidates in one file: noisier
    }
    return [float(v[k]) for k in FEATURES]


def _sigmoid(z: float) -> float:
    return 1 / (1 + math.exp(-max(-30.0, min(30.0, z))))


def fit(X: list[list[float]], y: list[int]) -> list[float]:
    w = [0.0] * len(FEATURES)
    n = max(1, len(X))
    for _ in range(EPOCHS):
        grad = [0.0] * len(w)
        for xi, yi in zip(X, y):
            err = _sigmoid(sum(a * b for a, b in zip(w, xi))) - yi
            for j, xj in enumerate(xi):
                grad[j] += err * xj
        for j in range(len(w)):
            w[j] -= LR * (grad[j] / n + (L2 * w[j] / n if j else 0.0))   # bias not regularised
    return w


def predict(w: list[float], x: list[float]) -> float:
    return _sigmoid(sum(a * b for a, b in zip(w, x)))


def load_weights(path: Path) -> list[float]:
    d = json.loads(path.read_text(encoding="utf-8"))
    if d["features"] != FEATURES:
        raise ValueError("feature list changed since the weights were trained")
    return d["weights"]
