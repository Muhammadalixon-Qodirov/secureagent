"""Fetch the RealVuln Flask subset as an independent evaluation set, pinned and frozen.

- Ground truth: RealVuln benchmark repo (Apache-2.0) at a pinned commit, Flask targets only.
- Targets: each app's GitHub archive at the commit_sha recorded in its ground truth.
- Hint removal (docs/realvuln_protocol.md): non-code files that describe the bugs
  (README*, *.md, *.rst, *.txt docs, LICENSE excluded) are deleted, and Python
  comments are blanked with the line structure kept, so ground-truth line
  numbers stay valid.
- Writes eval/realvuln/FROZEN.json with the commits and SHA-256 of every file.

Targets keep their own licenses and are not committed (eval/realvuln/targets is ignored).

    python scripts/fetch_realvuln.py
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import sys
import tokenize
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "eval" / "realvuln"
BENCH = "kolega-ai/Real-Vuln-Benchmark"
UA = {"User-Agent": "secagent-eval/0.1"}
HINT_FILES = re.compile(r"(?i)(^readme|\.md$|\.rst$|^hints?|^solutions?|^walkthrough|^writeup|^docs?$)")


def get(url: str) -> bytes:
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=120) as r:
        return r.read()


def blank_comments(src: str) -> str:
    """Remove '#' comments, keeping every line (and line numbers) in place."""
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(src).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return src                                    # leave unparsable files untouched
    lines = src.splitlines(keepends=True)
    for tok in reversed(tokens):
        if tok.type == tokenize.COMMENT:
            row, col = tok.start
            line = lines[row - 1]
            end = "\n" if line.endswith("\n") else ""
            lines[row - 1] = line[:col].rstrip() + end
    return "".join(lines)


def main() -> int:
    bench_sha = json.loads(get(f"https://api.github.com/repos/{BENCH}/commits/main"))["sha"]
    tree = json.loads(get(f"https://api.github.com/repos/{BENCH}/git/trees/{bench_sha}?recursive=1"))
    gt_paths = [t["path"] for t in tree["tree"] if t["path"].endswith("ground-truth.json")]
    targets = []
    gt_dir = OUT / "ground_truth"
    gt_dir.mkdir(parents=True, exist_ok=True)
    for p in gt_paths:
        gt = json.loads(get(f"https://raw.githubusercontent.com/{BENCH}/{bench_sha}/{p}"))
        if gt.get("language") != "python" or gt.get("framework") != "flask":
            continue
        (gt_dir / f"{gt['repo_id']}.json").write_text(json.dumps(gt, indent=2), encoding="utf-8")
        targets.append(gt)
    print(f"RealVuln {bench_sha[:12]}: {len(targets)} Flask targets")

    files_hash, removed = {}, {}
    for gt in targets:
        owner_repo = gt["repo_url"].rstrip("/").split("github.com/")[1]
        data = get(f"https://codeload.github.com/{owner_repo}/zip/{gt['commit_sha']}")
        dest = OUT / "targets" / gt["repo_id"]
        removed[gt["repo_id"]] = []
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            prefix = zf.namelist()[0].split("/")[0] + "/"
            for name in zf.namelist():
                rel = name[len(prefix):]
                if not rel or name.endswith("/"):
                    continue
                parts = rel.split("/")
                if any(HINT_FILES.search(x) for x in parts) and not parts[-1].upper().startswith("LICENSE"):
                    removed[gt["repo_id"]].append(rel)
                    continue
                raw = zf.read(name)
                if rel.endswith(".py"):
                    raw = blank_comments(raw.decode("utf-8", errors="replace")).encode("utf-8")
                target = dest / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
                files_hash[f"{gt['repo_id']}/{rel}"] = hashlib.sha256(raw).hexdigest()
        print(f"  {gt['repo_id']:42s} files={sum(1 for k in files_hash if k.startswith(gt['repo_id'] + '/'))} "
              f"removed_hint_files={len(removed[gt['repo_id']])}")
    frozen = {
        "frozen_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "benchmark": BENCH, "benchmark_commit": bench_sha,
        "targets": {gt["repo_id"]: {"repo_url": gt["repo_url"], "commit_sha": gt["commit_sha"]} for gt in targets},
        "removed_hint_files": removed,
        "combined_sha256": hashlib.sha256("".join(f"{k}:{v}\n" for k, v in sorted(files_hash.items())).encode()).hexdigest(),
        "files": files_hash,
    }
    (OUT / "FROZEN.json").write_text(json.dumps(frozen, indent=2), encoding="utf-8")
    print("frozen:", frozen["combined_sha256"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
