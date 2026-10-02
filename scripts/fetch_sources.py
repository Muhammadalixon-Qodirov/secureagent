"""Download the public security knowledge sources used by the agent.

Every downloaded file is recorded in data/sources.jsonl with its URL,
retrieval time, SHA-256, version/commit and license, so the knowledge base
can be rebuilt and audited. Run once with network access; review runs offline.

    python scripts/fetch_sources.py
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import time
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw"
SOURCES = ROOT / "data" / "sources.jsonl"

UA = {"User-Agent": "local-security-agent-ingest/0.1 (research; contact via repo)"}

CWE_ZIP_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
CWE_TOP25_URL = "https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html"
OWASP_TOP10_BASE = "https://owasp.org/Top10/2025/"
OWASP_TOP10_PAGES = [
    "A01_2025-Broken_Access_Control",
    "A02_2025-Security_Misconfiguration",
    "A03_2025-Software_Supply_Chain_Failures",
    "A04_2025-Cryptographic_Failures",
    "A05_2025-Injection",
    "A06_2025-Insecure_Design",
    "A07_2025-Authentication_Failures",
    "A08_2025-Software_or_Data_Integrity_Failures",
    "A09_2025-Security_Logging_and_Alerting_Failures",
    "A10_2025-Mishandling_of_Exceptional_Conditions",
]

CHEATSHEET_REPO = "OWASP/CheatSheetSeries"
# Defensive guidance relevant to reviewing Python/Flask web code.
# Payload/evasion catalogues (e.g. XSS_Filter_Evasion) are deliberately excluded:
# the agent needs to recognise unsafe code and fixes, not attack strings.
CHEATSHEETS = [
    "SQL_Injection_Prevention_Cheat_Sheet.md",
    "Query_Parameterization_Cheat_Sheet.md",
    "Injection_Prevention_Cheat_Sheet.md",
    "OS_Command_Injection_Defense_Cheat_Sheet.md",
    "Cross_Site_Scripting_Prevention_Cheat_Sheet.md",
    "Authorization_Cheat_Sheet.md",
    "Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.md",
    "Input_Validation_Cheat_Sheet.md",
    "File_Upload_Cheat_Sheet.md",
    "Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md",
    "Deserialization_Cheat_Sheet.md",
    "Mass_Assignment_Cheat_Sheet.md",
    "Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md",
    "Session_Management_Cheat_Sheet.md",
    "Authentication_Cheat_Sheet.md",
    "Password_Storage_Cheat_Sheet.md",
    "Cryptographic_Storage_Cheat_Sheet.md",
    "Secrets_Management_Cheat_Sheet.md",
    "Error_Handling_Cheat_Sheet.md",
    "Logging_Cheat_Sheet.md",
    "Vulnerable_Dependency_Management_Cheat_Sheet.md",
    "Transaction_Authorization_Cheat_Sheet.md",
    "LLM_Prompt_Injection_Prevention_Cheat_Sheet.md",
]

# Official framework/runtime security documentation (HTML pages).
OFFICIAL_DOCS = [
    ("flask_web_security", "https://flask.palletsprojects.com/en/stable/web-security/", "BSD-3-Clause (Pallets docs)"),
    ("flask_templating", "https://flask.palletsprojects.com/en/stable/templating/", "BSD-3-Clause (Pallets docs)"),
    ("flask_login", "https://flask-login.readthedocs.io/en/latest/", "MIT (Flask-Login docs)"),
    ("werkzeug_safe_join", "https://werkzeug.palletsprojects.com/en/stable/utils/", "BSD-3-Clause (Pallets docs)"),
    ("jinja_autoescape", "https://jinja.palletsprojects.com/en/stable/api/", "BSD-3-Clause (Pallets docs)"),
    ("sqlalchemy_text", "https://docs.sqlalchemy.org/en/20/core/sqlelement.html", "MIT (SQLAlchemy docs)"),
    ("owasp_path_traversal", "https://owasp.org/www-community/attacks/Path_Traversal", "CC-BY-SA-4.0"),
]

# Python stdlib docs are taken from the CPython source tree (reST), pinned to a
# commit of the 3.13 branch, instead of docs.python.org HTML.
CPYTHON_BRANCH = "3.13"
CPYTHON_DOCS = ["sqlite3", "subprocess", "pickle", "os.path", "tempfile", "secrets", "hmac"]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class _Redirects(urllib.request.HTTPRedirectHandler):
    # Python < 3.11 does not follow 308 Permanent Redirect (owasp.org uses it).
    http_error_308 = urllib.request.HTTPRedirectHandler.http_error_302

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if code == 308:
            code = 307
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_Redirects)


def _get(url: str, retries: int = 3) -> bytes:
    last: Exception | None = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=UA)
            with _OPENER.open(req, timeout=60) as resp:
                return resp.read()
        except Exception as exc:  # network errors are retried, then reported
            last = exc
            time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"download failed: {url}: {last}")


class SourceLog:
    def __init__(self) -> None:
        self.records: list[dict] = []

    def save(self, source_id: str, url: str, data: bytes, dest: Path,
             license_: str, version: str | None, kind: str) -> None:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        self.records.append({
            "id": source_id,
            "kind": kind,
            "url": url,
            "path": dest.relative_to(ROOT).as_posix(),
            "version_or_commit": version,
            "retrieved_at": _now(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
            "license": license_,
        })
        print(f"  ok  {source_id:55s} {len(data):>9,d} B")

    def write(self) -> None:
        SOURCES.parent.mkdir(parents=True, exist_ok=True)
        with SOURCES.open("w", encoding="utf-8") as fh:
            for rec in self.records:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")


def fetch_cwe(log: SourceLog) -> None:
    print("[cwe] MITRE CWE XML")
    data = _get(CWE_ZIP_URL)
    dest = RAW / "cwe" / "cwec_latest.xml.zip"
    with zipfile.ZipFile(__import__("io").BytesIO(data)) as zf:
        xml_name = next(n for n in zf.namelist() if n.endswith(".xml"))
        version = re.search(r"cwec_(v[\d.]+)\.xml", xml_name)
    log.save("mitre-cwe-xml", CWE_ZIP_URL, data, dest,
             "MITRE CWE Terms of Use", version.group(1) if version else xml_name, "dataset")

    print("[cwe] 2025 CWE Top 25")
    page = _get(CWE_TOP25_URL)
    log.save("mitre-cwe-top25-2025", CWE_TOP25_URL, page, RAW / "cwe" / "top25_2025.html",
             "MITRE CWE Terms of Use", "2025", "ranking")


def fetch_owasp_top10(log: SourceLog) -> None:
    print("[owasp] Top 10:2025")
    for slug in OWASP_TOP10_PAGES:
        url = OWASP_TOP10_BASE + slug
        log.save(f"owasp-top10-2025-{slug[:3].lower()}", url, _get(url),
                 RAW / "owasp_top10_2025" / f"{slug}.html", "CC-BY-SA-4.0", "2025", "ranking")


def fetch_cheatsheets(log: SourceLog) -> None:
    print("[owasp] Cheat Sheet Series")
    meta = json.loads(_get(f"https://api.github.com/repos/{CHEATSHEET_REPO}/commits/master"))
    sha = meta["sha"]
    print(f"  pinned commit {sha}")
    for name in CHEATSHEETS:
        url = f"https://raw.githubusercontent.com/{CHEATSHEET_REPO}/{sha}/cheatsheets/{name}"
        try:
            data = _get(url)
        except RuntimeError as exc:
            print(f"  MISSING {name}: {exc}", file=sys.stderr)
            continue
        log.save("owasp-cs-" + name.removesuffix("_Cheat_Sheet.md").lower(), url, data,
                 RAW / "owasp_cheatsheets" / name, "CC-BY-SA-4.0", sha, "guidance")


def fetch_official_docs(log: SourceLog) -> None:
    print("[docs] official framework/runtime docs")
    for sid, url, lic in OFFICIAL_DOCS:
        try:
            data = _get(url)
        except RuntimeError as exc:
            print(f"  MISSING {sid}: {exc}", file=sys.stderr)
            continue
        log.save(f"doc-{sid}", url, data, RAW / "official_docs" / f"{sid}.html", lic, None, "documentation")

    meta = json.loads(_get(f"https://api.github.com/repos/python/cpython/commits/{CPYTHON_BRANCH}"))
    sha = meta["sha"]
    print(f"  cpython {CPYTHON_BRANCH} pinned commit {sha}")
    for mod in CPYTHON_DOCS:
        url = f"https://raw.githubusercontent.com/python/cpython/{sha}/Doc/library/{mod}.rst"
        try:
            data = _get(url)
        except RuntimeError as exc:
            print(f"  MISSING python {mod}: {exc}", file=sys.stderr)
            continue
        log.save(f"doc-python-{mod.replace('.', '_')}", url, data,
                 RAW / "official_docs" / f"python_{mod.replace('.', '_')}.rst", "PSF-2.0", sha, "documentation")


def main() -> int:
    log = SourceLog()
    fetch_cwe(log)
    fetch_owasp_top10(log)
    fetch_cheatsheets(log)
    fetch_official_docs(log)
    log.write()
    print(f"\n{len(log.records)} sources -> {SOURCES.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
