"""Build the CVE-replay evaluation set (docs/cve_replay_protocol.md).

Source: the public OSV dump for PyPI. For every advisory published in 2026 in one of the
three MVP families that links exactly one GitHub fix commit, two snapshots are stored:
the parent of the fix (vulnerable) and the fix itself (fixed). Only the review scope is
kept - the changed non-test Python files plus the other Python files of their directories,
within a size cap - so this is a "directory given" test, not whole-repository discovery.

The split is decided before anything is fetched and by REPOSITORY, so no codebase is in
both halves: first hex digit of sha256("owner/repo") even -> dev, odd -> test. Within a split
and family the first PER_FAMILY advisories in sha256(advisory id) order that can be built are
kept, at most PER_REPO per repository. Version files and import-only hunks are not locations.

    python scripts/build_cve_replay.py [--per-family 12] [--only dev|test]

Targets keep their own licences and are not committed (eval/cve_replay/*/targets is ignored).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fetch_realvuln import blank_comments  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "eval" / "cve_replay"
OSV_URL = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"
FAMILY = {"CWE-89": "sql_injection", "CWE-564": "sql_injection", "CWE-943": "sql_injection",
          "CWE-22": "path_traversal", "CWE-23": "path_traversal", "CWE-36": "path_traversal", "CWE-73": "path_traversal",
          "CWE-639": "authorization_idor", "CWE-862": "authorization_idor", "CWE-863": "authorization_idor",
          "CWE-284": "authorization_idor", "CWE-285": "authorization_idor", "CWE-306": "authorization_idor"}
COMMIT = re.compile(r"https://github\.com/([^/\s]+)/([^/\s]+)/commit/([0-9a-f]{7,40})")
TEST_PATH = re.compile(r"(^|/)(tests?|testing|docs?|examples?|benchmarks?)/|(^|/)(test_[^/]*|[^/]*_test|conftest|setup)\.py$")
YEAR = "2026"
MAX_CHANGED = 5                 # changed non-test Python files
PER_REPO = 2                    # advisories of one repository per split
VERSION_FILE = re.compile(r"(^|/)(_?version|__about__|__version__|_meta)\.py$")
IMPORT_LINE = re.compile(r"^\s*(import\s|from\s+\S+\s+import\s|$|\)|[\w, ]+,?\s*$)")
MAX_SCOPE_FILES = 25
MAX_SCOPE_BYTES = 250_000
WORK = Path(tempfile.gettempdir()) / "secagent_cve"     # git work trees: outside any synced folder
HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", re.M)


def git(cwd: Path, *args: str, timeout: int = 180, stdin: str | None = None) -> str:
    env = {"GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never"}
    import os
    r = subprocess.run(["git", "-c", "credential.helper=", "-c", "core.longpaths=true", *args], cwd=cwd,
                       capture_output=True, timeout=timeout, env={**os.environ, **env},
                       input=None if stdin is None else stdin.encode())
    if r.returncode != 0:
        raise RuntimeError(r.stderr.decode("utf-8", "replace")[-300:])
    return r.stdout.decode("utf-8", "replace")


def rmtree(path: Path) -> None:
    import os
    import stat

    def writable(func, target, _exc):
        os.chmod(target, stat.S_IWRITE)
        func(target)
    shutil.rmtree(path, onerror=writable) if path.exists() else None


def candidates(zip_path: Path) -> list[dict]:
    out = []
    with zipfile.ZipFile(zip_path) as z:
        for name in z.namelist():
            d = json.loads(z.read(name))
            if d.get("withdrawn") or not (d.get("published") or "").startswith(YEAR):
                continue
            cwes = (d.get("database_specific") or {}).get("cwe_ids") or []
            fams = {FAMILY[c] for c in cwes if c in FAMILY}
            if len(fams) != 1:
                continue
            commits = {m.groups() for r in d.get("references", []) for m in [COMMIT.search(r.get("url", ""))] if m}
            if len({c[2][:7] for c in commits}) != 1:
                continue
            owner, repo, sha = sorted(commits, key=lambda c: -len(c[2]))[0]
            repo = repo.removesuffix(".git")
            h = hashlib.sha256(d["id"].encode()).hexdigest()
            rh = hashlib.sha256(f"{owner}/{repo}".lower().encode()).hexdigest()
            out.append({"id": d["id"], "family": fams.pop(), "cwes": sorted(c for c in cwes if c in FAMILY),
                        "published": d["published"][:10], "owner": owner, "repo": repo, "sha": sha,
                        "hash": h, "split": "dev" if int(rh[0], 16) % 2 == 0 else "test"})
    return sorted(out, key=lambda c: c["hash"])


def ranges(diff: str) -> tuple[list[list[int]], list[list[int]]]:
    """Old-side and new-side line ranges of a -U0 diff of one file (an insertion is its insertion point)."""
    old, new = [], []
    for m in HUNK.finditer(diff):
        a, al, b, bl = int(m.group(1)), int(m.group(2) or 1), int(m.group(3)), int(m.group(4) or 1)
        old.append([max(a, 1), max(a, 1) + max(al, 1) - 1])
        new.append([max(b, 1), max(b, 1) + max(bl, 1) - 1])
    return old, new


def build(c: dict, cache: Path, dest: Path) -> dict:
    """Fetch the fix commit and its parent (blobless, depth 2) and write both scoped snapshots."""
    repo_dir = cache / f"{c['owner']}__{c['repo']}__{c['sha'][:12]}"
    rmtree(repo_dir)
    repo_dir.mkdir(parents=True)
    try:
        git(repo_dir, "init", "-q")
        git(repo_dir, "remote", "add", "origin", f"https://github.com/{c['owner']}/{c['repo']}.git")
        git(repo_dir, "fetch", "-q", "--depth", "2", "--filter=blob:none", "origin", c["sha"], timeout=300)
        full = git(repo_dir, "rev-parse", "FETCH_HEAD").strip()
        parents = git(repo_dir, "rev-list", "--parents", "-n", "1", full).split()[1:]
        if len(parents) != 1:
            raise RuntimeError(f"{len(parents)} parents")
        parent = parents[0]
        changed = [p for p in git(repo_dir, "diff", "--name-only", "--diff-filter=M", parent, full).splitlines()
                   if p.endswith(".py") and not TEST_PATH.search(p) and not VERSION_FILE.search(p)]
        if not changed or len(changed) > MAX_CHANGED:
            raise RuntimeError(f"{len(changed)} changed non-test python files")
        files = []
        for p in changed:
            old, new = ranges(git(repo_dir, "diff", "-U0", parent, full, "--", p))
            before = git(repo_dir, "show", f"{parent}:{p}", timeout=120).splitlines()
            after = git(repo_dir, "show", f"{full}:{p}", timeout=120).splitlines()
            keep = [i for i, ((a, b), (c2, d2)) in enumerate(zip(old, new))     # a hunk that only edits imports
                    if not (all(IMPORT_LINE.match(x) for x in before[a - 1:b])  # is not where the bug is
                            and all(IMPORT_LINE.match(x) for x in after[c2 - 1:d2]))]
            if keep:
                files.append({"path": p, "vulnerable_ranges": [old[i] for i in keep],
                              "fixed_ranges": [new[i] for i in keep]})
        if not files:
            raise RuntimeError("no hunks outside imports")
        changed = [f["path"] for f in files]
        dirs = sorted({str(Path(p).parent.as_posix()) for p in changed})
        scope, size = list(changed), 0
        for d in dirs:                          # siblings of the changed files, in name order, within the caps
            listing = git(repo_dir, "ls-tree", "--name-only", parent, *([d + "/"] if d != "." else [])).splitlines()
            for p in sorted(listing):
                if p.endswith(".py") and p not in scope and not TEST_PATH.search(p) and len(scope) < MAX_SCOPE_FILES:
                    scope.append(p)
        hashes = {}
        for rev, label in ((parent, "vulnerable"), (full, "fixed")):
            size = 0
            # one batched fetch of the scope's blobs (what a lazy partial-clone fetch does, for all at once)
            blobs = dict(reversed(line.split(None, 3)[2:4]) for line in
                         git(repo_dir, "ls-tree", "-r", rev, "--", *scope).replace("\t", " ").splitlines())
            wanted = [p for p in scope if p in blobs]
            git(repo_dir, "-c", "fetch.negotiationAlgorithm=noop", "fetch", "-q", "origin", "--no-tags",
                "--no-write-fetch-head", "--recurse-submodules=no", "--filter=blob:none", "--stdin",
                stdin="\n".join(blobs[p] for p in wanted) + "\n", timeout=300)
            for p in wanted:
                raw = git(repo_dir, "show", f"{rev}:{p}", timeout=120)
                size += len(raw)
                if size > MAX_SCOPE_BYTES and p not in changed:
                    break
                text = blank_comments(raw)
                target = dest / c["id"] / label / p
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(text.encode("utf-8"))
                hashes[f"{c['id']}/{label}/{p}"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
        return {"id": c["id"], "family": c["family"], "cwes": c["cwes"], "published": c["published"],
                "repo_url": f"https://github.com/{c['owner']}/{c['repo']}", "fix_commit": full, "parent_commit": parent,
                "files": files, "scope_files": len(scope), "_hashes": hashes}
    finally:
        try:
            rmtree(repo_dir)
        except OSError:
            pass


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-family", type=int, default=12)
    ap.add_argument("--only", choices=["dev", "test"])
    ap.add_argument("--fresh", metavar="NAME",
                    help="build a further half NAME from advisories in repositories that no existing half uses "
                         "(one advisory per repository)")
    a = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    zip_path = OUT / "_cache" / "pypi_osv.zip"
    zip_path.parent.mkdir(exist_ok=True)
    if not zip_path.exists():
        with urllib.request.urlopen(urllib.request.Request(OSV_URL, headers={"User-Agent": "secagent-eval/0.1"}),
                                    timeout=300) as r:
            zip_path.write_bytes(r.read())
    osv_sha = hashlib.sha256(zip_path.read_bytes()).hexdigest()
    cands = candidates(zip_path)
    print(f"OSV dump {osv_sha[:12]}: {len(cands)} candidate advisories "
          f"(dev {sum(c['split'] == 'dev' for c in cands)}, test {sum(c['split'] == 'test' for c in cands)})")
    used_repos: set[str] = set()
    if a.fresh:                                             # repositories already in any half are off limits
        for gt in OUT.glob("*/ground_truth.json"):
            if gt.parent.name != a.fresh:
                used_repos |= {e["repo_url"].split("github.com/")[1].lower()
                               for e in json.loads(gt.read_text(encoding="utf-8"))}
        for c in cands:
            c["split"] = a.fresh if f"{c['owner']}/{c['repo']}".lower() not in used_repos else "used"
        print(f"fresh half {a.fresh!r}: {sum(c['split'] == a.fresh for c in cands)} candidates in unused repositories")
    for split in ([a.fresh] if a.fresh else [a.only] if a.only else ["dev", "test"]):
        dest = OUT / split / "targets"
        if dest.exists():
            shutil.rmtree(dest)
        kept, skipped, hashes = [], [], {}
        count = {f: 0 for f in set(FAMILY.values())}
        per_repo: dict[str, int] = {}
        for c in (x for x in cands if x["split"] == split):
            key = f"{c['owner']}/{c['repo']}".lower()
            if count[c["family"]] >= a.per_family or per_repo.get(key, 0) >= (1 if a.fresh else PER_REPO):
                continue
            try:
                e = build(c, WORK, dest)
            except Exception as exc:                       # noqa: BLE001 - recorded, not hidden
                shutil.rmtree(dest / c["id"], ignore_errors=True)
                skipped.append({"id": c["id"], "reason": f"{type(exc).__name__}: {str(exc)[:160]}"})
                continue
            hashes.update(e.pop("_hashes"))
            kept.append(e)
            count[c["family"]] += 1
            per_repo[key] = per_repo.get(key, 0) + 1
            print(f"  [{split}] {len(kept):3d} kept ({', '.join(f'{k[:4]} {v}' for k, v in sorted(count.items()))})"
                  f", {len(skipped)} skipped", flush=True)
        combined = hashlib.sha256("".join(f"{k}:{v}\n" for k, v in sorted(hashes.items())).encode()).hexdigest()
        (OUT / split / "ground_truth.json").write_text(json.dumps(kept, indent=2), encoding="utf-8")
        (OUT / split / "FROZEN.json").write_text(json.dumps({
            "frozen_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "osv_dump_sha256": osv_sha,
            "year": YEAR, "per_family": a.per_family, "per_repo": PER_REPO, "entries": len(kept),
            "by_family": count, "repositories": len(per_repo),
            "skipped": skipped, "combined_sha256": combined, "files": hashes}, indent=2), encoding="utf-8")
        print(f"{split}: {len(kept)} entries {count}, {len(skipped)} skipped, frozen {combined[:16]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
