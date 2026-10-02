"""Turn downloaded sources (data/raw, data/sources.jsonl) into the local knowledge base.

Outputs
  data/knowledge/cwe.jsonl            structured CWE entries (catalog CWEs only)
  data/knowledge/owasp_top10_2025.json category -> mapped CWE ids
  data/knowledge/chunks.jsonl         retrieval chunks with provenance
  data/security_catalog.yaml          vulnerability families, CWE/OWASP mapping, support level

Every CWE id used by the catalog must exist in the downloaded MITRE XML; the
build fails otherwise, so the catalog cannot contain invented identifiers.

    python scripts/build_knowledge.py
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import sys
import zipfile
from pathlib import Path

import yaml
from lxml import etree, html

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
RAW = DATA / "raw"
OUT = DATA / "knowledge"
NS = {"c": "http://cwe.mitre.org/cwe-7"}

MAX_CHUNK_CHARS = 2400

# Large API reference pages are mostly unrelated to security. For these sources
# a chunk is kept only if it mentions one of the listed terms; otherwise e.g.
# werkzeug's cached_property docs would be indexed under CWE-22.
RELEVANCE_FILTER = {
    "doc-werkzeug_safe_join": ["safe_join", "secure_filename", "path traversal"],
    "doc-sqlalchemy_text": ["text(", "bindparam", "bound parameter", "sql injection", "literal_column", "textclause"],
    "doc-jinja_autoescape": ["autoescape", "markup", "escape", "select_autoescape"],
    "doc-python-sqlite3": ["placeholder", "sql injection", "execute(", "parameter"],
    "doc-python-subprocess": ["shell", "security", "shlex", "injection"],
    "doc-python-pickle": ["untrusted", "secure", "unpickler", "warning", "find_class", "hmac"],
    "doc-python-os_path": ["realpath", "abspath", "commonpath", "normpath", "join(", "symlink"],
    "doc-python-tempfile": ["mkstemp", "mktemp", "insecure", "race", "security"],
    "doc-flask_login": ["login_required", "current_user", "unauthorized", "fresh_login"],
}
# Security warnings are kept from any filtered page even without a listed term.
RELEVANCE_ALWAYS = ["untrusted", "injection", "security"]

# Vulnerability families the agent knows about. `mvp` marks the families the
# two-week MVP is built around; support_level is "documented_only" until a
# detector + evaluation exist for the family (then it becomes "implemented").
FAMILIES: list[dict] = [
    {"id": "sql_injection", "name": "SQL injection", "cwe": [89, 564], "mvp": True,
     "sources": ["owasp-cs-sql_injection_prevention", "owasp-cs-query_parameterization",
                 "owasp-cs-injection_prevention", "doc-python-sqlite3", "doc-sqlalchemy_text"]},
    {"id": "path_traversal", "name": "Path traversal / unsafe file path", "cwe": [22, 23, 36, 73], "mvp": True,
     "sources": ["doc-owasp_path_traversal", "owasp-cs-input_validation", "owasp-cs-file_upload",
                 "doc-werkzeug_safe_join", "doc-python-os_path"]},
    {"id": "authorization_idor", "name": "Broken authorization / IDOR", "cwe": [639, 862, 863, 284, 285], "mvp": True,
     "sources": ["owasp-cs-authorization", "owasp-cs-insecure_direct_object_reference_prevention",
                 "owasp-cs-transaction_authorization", "doc-flask_login"]},
    {"id": "os_command_injection", "name": "OS command injection", "cwe": [78, 77, 88], "mvp": "stretch",
     "sources": ["owasp-cs-os_command_injection_defense", "doc-python-subprocess"]},
    {"id": "xss", "name": "Cross-site scripting", "cwe": [79, 80, 116], "mvp": "stretch",
     "sources": ["owasp-cs-cross_site_scripting_prevention", "doc-jinja_autoescape", "doc-flask_web_security", "doc-flask_templating"]},
    {"id": "code_injection", "name": "Code / eval injection", "cwe": [94, 95], "mvp": False,
     "sources": ["owasp-cs-injection_prevention"]},
    {"id": "missing_authentication", "name": "Missing authentication for critical function", "cwe": [306, 287],
     "mvp": False, "sources": ["owasp-cs-authentication"]},
    {"id": "ssrf", "name": "Server-side request forgery", "cwe": [918], "mvp": False,
     "sources": ["owasp-cs-server_side_request_forgery_prevention"]},
    {"id": "file_upload", "name": "Unrestricted file upload", "cwe": [434], "mvp": False,
     "sources": ["owasp-cs-file_upload"]},
    {"id": "csrf", "name": "Cross-site request forgery", "cwe": [352], "mvp": False,
     "sources": ["owasp-cs-cross-site_request_forgery_prevention", "doc-flask_web_security"]},
    {"id": "session_token", "name": "Session / token management", "cwe": [384, 613, 347, 1004, 614], "mvp": False,
     "sources": ["owasp-cs-session_management", "doc-flask_web_security"]},
    {"id": "deserialization", "name": "Insecure deserialization", "cwe": [502], "mvp": False,
     "sources": ["owasp-cs-deserialization", "doc-python-pickle"]},
    {"id": "mass_assignment", "name": "Mass assignment", "cwe": [915], "mvp": False,
     "sources": ["owasp-cs-mass_assignment"]},
    {"id": "secrets_configuration", "name": "Hard-coded secrets / insecure configuration", "cwe": [798, 259, 321, 489],
     "mvp": False, "sources": ["owasp-cs-secrets_management", "doc-flask_web_security"]},
    {"id": "weak_cryptography", "name": "Weak cryptography / randomness / password storage",
     "cwe": [327, 328, 916, 330, 338, 295], "mvp": False,
     "sources": ["owasp-cs-cryptographic_storage", "owasp-cs-password_storage", "doc-python-secrets", "doc-python-hmac"]},
    {"id": "information_exposure", "name": "Information exposure / error handling", "cwe": [200, 209, 532, 755],
     "mvp": False, "sources": ["owasp-cs-error_handling", "owasp-cs-logging"]},
    {"id": "dependency_risk", "name": "Vulnerable or unmaintained dependencies", "cwe": [1104, 1395], "mvp": False,
     "sources": ["owasp-cs-vulnerable_dependency_management"]},
    {"id": "input_validation", "name": "Improper input validation (general)", "cwe": [20], "mvp": False,
     "sources": ["owasp-cs-input_validation"]},
    {"id": "resource_exhaustion", "name": "Uncontrolled resource consumption", "cwe": [770, 400], "mvp": False,
     "sources": []},
    {"id": "memory_safety", "name": "Memory safety (C/C++)", "cwe": [787, 416, 125, 120, 121, 122, 476],
     "mvp": False, "sources": [], "unsupported_reason":
         "MVP reviews Python/Flask code; memory-safety weaknesses require native-code analysis."},
]


# ---------------------------------------------------------------- helpers

def _text(el) -> str:
    if el is None:
        return ""
    return re.sub(r"\s+", " ", " ".join(el.itertext())).strip()


def _hash(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def load_sources() -> dict[str, dict]:
    recs = [json.loads(l) for l in (DATA / "sources.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    return {r["id"]: r for r in recs}


# ---------------------------------------------------------------- CWE

def load_cwe_xml(src: dict) -> etree._Element:
    with zipfile.ZipFile(ROOT / src["path"]) as zf:
        name = next(n for n in zf.namelist() if n.endswith(".xml"))
        return etree.parse(io.BytesIO(zf.read(name))).getroot()


def parse_weakness(w) -> dict:
    def many(path: str) -> list:
        return w.findall(path, NS)

    mitigations = []
    for m in many("c:Potential_Mitigations/c:Mitigation"):
        mitigations.append({
            "phase": [_text(p) for p in m.findall("c:Phase", NS)],
            "strategy": _text(m.find("c:Strategy", NS)) or None,
            "description": _text(m.find("c:Description", NS)),
            "effectiveness": _text(m.find("c:Effectiveness", NS)) or None,
        })
    consequences = []
    for c in many("c:Common_Consequences/c:Consequence"):
        consequences.append({
            "scope": [_text(s) for s in c.findall("c:Scope", NS)],
            "impact": [_text(i) for i in c.findall("c:Impact", NS)],
            "note": _text(c.find("c:Note", NS)) or None,
        })
    detection = []
    for d in many("c:Detection_Methods/c:Detection_Method"):
        detection.append({
            "method": _text(d.find("c:Method", NS)),
            "description": _text(d.find("c:Description", NS)),
            "effectiveness": _text(d.find("c:Effectiveness", NS)) or None,
        })
    related = [
        {"nature": r.get("Nature"), "cwe_id": f"CWE-{r.get('CWE_ID')}"}
        for r in many("c:Related_Weaknesses/c:Related_Weakness")
    ]
    langs = sorted({l.get("Name") or l.get("Class") for l in many("c:Applicable_Platforms/c:Language")} - {None})
    return {
        "cwe_id": f"CWE-{w.get('ID')}",
        "name": w.get("Name"),
        "abstraction": w.get("Abstraction"),
        "status": w.get("Status"),
        "description": _text(w.find("c:Description", NS)),
        "extended_description": _text(w.find("c:Extended_Description", NS)) or None,
        "languages": langs,
        "consequences": consequences,
        "mitigations": mitigations,
        "detection_methods": detection,
        "related_weaknesses": related,
    }


def parse_top25(src: dict) -> list[str]:
    page = (ROOT / src["path"]).read_text(encoding="utf-8", errors="ignore")
    ranked: list[str] = []
    for i in re.findall(r"CWE-(\d+)", page):
        cid = f"CWE-{i}"
        if cid not in ranked:
            ranked.append(cid)
    if len(ranked) != 25:
        raise SystemExit(f"expected 25 CWE ids in Top 25 page, found {len(ranked)}")
    return ranked


# ---------------------------------------------------------------- OWASP Top 10

def parse_owasp_top10(sources: dict[str, dict]) -> dict[str, dict]:
    out = {}
    for sid, src in sorted(sources.items()):
        if not sid.startswith("owasp-top10-2025-"):
            continue
        page = (ROOT / src["path"]).read_text(encoding="utf-8", errors="ignore")
        slug = Path(src["path"]).stem                      # A01_2025-Broken_Access_Control
        code, title = slug.split("-", 1)
        idx = page.find("List of Mapped CWEs")
        mapped = sorted({int(x) for x in re.findall(r"definitions/(\d+)\.html", page[idx:])}) if idx >= 0 else []
        out[code.replace("_", ":")] = {
            "title": title.replace("_", " "),
            "url": src["url"],
            "source_id": sid,
            "mapped_cwes": [f"CWE-{i}" for i in mapped],
        }
    return out


# ---------------------------------------------------------------- chunking

_SEPARATORS = [r"\n\s*\n", r"\n", r"(?<=[.!?])\s+", r"\s+"]


def _split_long(text: str, level: int = 0) -> list[str]:
    """Pack text into <= MAX_CHUNK_CHARS pieces, splitting on the coarsest
    separator that works: paragraphs, then lines, sentences, words."""
    text = text.strip()
    if len(text) <= MAX_CHUNK_CHARS:
        return [text] if text else []
    if level >= len(_SEPARATORS):
        return [text[i:i + MAX_CHUNK_CHARS] for i in range(0, len(text), MAX_CHUNK_CHARS)]
    joiner = "\n\n" if level == 0 else ("\n" if level == 1 else " ")
    pieces: list[str] = []
    for unit in re.split(_SEPARATORS[level], text):
        pieces.extend(_split_long(unit, level + 1) if len(unit) > MAX_CHUNK_CHARS else [unit])
    parts, cur = [], ""
    for p in pieces:
        if not p.strip():
            continue
        if cur and len(cur) + len(joiner) + len(p) > MAX_CHUNK_CHARS:
            parts.append(cur.strip())
            cur = ""
        cur = f"{cur}{joiner}{p}" if cur else p
    if cur.strip():
        parts.append(cur.strip())
    return parts


def sections_markdown(text: str) -> list[tuple[str, str]]:
    secs, title, buf = [], "Introduction", []
    for line in text.splitlines():
        m = re.match(r"^(#{1,4})\s+(.*)", line)
        if m:
            if "".join(buf).strip():
                secs.append((title, "\n".join(buf).strip()))
            title, buf = m.group(2).strip(), []
        else:
            buf.append(line)
    if "".join(buf).strip():
        secs.append((title, "\n".join(buf).strip()))
    return secs


def sections_rst(text: str) -> list[tuple[str, str]]:
    lines = text.splitlines()
    secs, title, buf = [], "Introduction", []
    i = 0
    while i < len(lines):
        nxt = lines[i + 1] if i + 1 < len(lines) else ""
        if lines[i].strip() and re.fullmatch(r"([=\-~^\"'*+#])\1{2,}", nxt.strip()) and len(nxt.strip()) >= len(lines[i].strip()) - 2:
            if "".join(buf).strip():
                secs.append((title, "\n".join(buf).strip()))
            title, buf = lines[i].strip(), []
            i += 2
            continue
        buf.append(lines[i])
        i += 1
    if "".join(buf).strip():
        secs.append((title, "\n".join(buf).strip()))
    return secs


_HTML_BLOCKS = ("p", "li", "pre", "td", "dt", "dd")


def sections_html(raw: str) -> list[tuple[str, str]]:
    doc = html.fromstring(raw)
    for bad in doc.xpath("//script|//style|//nav|//header|//footer|//aside"):
        bad.drop_tree()
    main = (doc.xpath("//main") or doc.xpath("//article") or doc.xpath("//div[@role='main']") or [doc])[0]
    secs, title, buf = [], "Introduction", []
    for el in main.iter():
        tag = el.tag if isinstance(el.tag, str) else ""
        if tag in ("h1", "h2", "h3"):
            if " ".join(buf).strip():
                secs.append((title, "\n".join(buf).strip()))
            title, buf = _text(el).rstrip("¶ ").strip() or title, []
        elif tag in _HTML_BLOCKS:
            # nested blocks (p inside li, li inside dd ...) are already part of the outer text
            if any(isinstance(a.tag, str) and a.tag in _HTML_BLOCKS for a in el.iterancestors()):
                continue
            t = el.text_content().strip() if tag == "pre" else _text(el)
            if t:
                buf.append(t)
    if " ".join(buf).strip():
        secs.append((title, "\n".join(buf).strip()))
    return secs


def chunk_source(src: dict, cwe_by_source: dict[str, list[str]]) -> list[dict]:
    path = ROOT / src["path"]
    raw = path.read_text(encoding="utf-8", errors="ignore")
    if path.suffix == ".md":
        secs = sections_markdown(raw)
    elif path.suffix == ".rst":
        secs = sections_rst(raw)
    else:
        secs = sections_html(raw)
    doc_title = secs[0][0] if secs else src["id"]
    terms = RELEVANCE_FILTER.get(src["id"])
    chunks = []
    for n, (title, body) in enumerate(secs):
        body = re.sub(r"\n{3,}", "\n\n", body).strip()
        if len(body) < 80:            # headings / navigation stubs
            continue
        for k, part in enumerate(_split_long(body)):
            if terms and not any(t in (title + " " + part).lower() for t in terms + RELEVANCE_ALWAYS):
                continue
            chunks.append({
                "id": f"{src['id']}#{n:03d}.{k}",
                "source_id": src["id"],
                "title": f"{doc_title} — {title}" if title != doc_title else title,
                "text": part,
                "source_url": src["url"],
                "source_version_or_commit": src["version_or_commit"],
                "retrieved_at": src["retrieved_at"],
                "license": src["license"],
                "cwe_ids": cwe_by_source.get(src["id"], []),
                "content_hash": _hash(part),
            })
    return chunks


def chunk_cwe(entry: dict, src: dict) -> list[dict]:
    lines = [f"{entry['cwe_id']}: {entry['name']} ({entry['abstraction']}, status {entry['status']})",
             entry["description"]]
    if entry["extended_description"]:
        lines.append(entry["extended_description"])
    parts = ["\n\n".join(lines)]
    if entry["consequences"]:
        parts.append("Common consequences:\n" + "\n".join(
            f"- {', '.join(c['scope'])}: {', '.join(c['impact'])}" + (f" — {c['note']}" if c["note"] else "")
            for c in entry["consequences"]))
    if entry["mitigations"]:
        parts.append("Potential mitigations:\n" + "\n".join(
            f"- [{'/'.join(m['phase']) or 'n/a'}{'; ' + m['strategy'] if m['strategy'] else ''}] {m['description']}"
            + (f" (effectiveness: {m['effectiveness']})" if m["effectiveness"] else "")
            for m in entry["mitigations"]))
    if entry["detection_methods"]:
        parts.append("Detection methods:\n" + "\n".join(
            f"- {d['method']}: {d['description']}" for d in entry["detection_methods"]))
    chunks = []
    for n, part in enumerate(parts):
        label = part.split("\n", 1)[0] if n else ""
        for k, piece in enumerate(_split_long(part)):
            if n == 0 and k == 0:
                text = piece
            else:
                cont = f" — {label}" if label and not piece.startswith(label) else ""
                text = f"{entry['cwe_id']} {entry['name']}{cont}\n{piece}"
            chunks.append({
                "id": f"{entry['cwe_id']}#{n}.{k}",
                "source_id": src["id"],
                "title": f"{entry['cwe_id']}: {entry['name']}",
                "text": text,
                "source_url": f"https://cwe.mitre.org/data/definitions/{entry['cwe_id'][4:]}.html",
                "source_version_or_commit": src["version_or_commit"],
                "retrieved_at": src["retrieved_at"],
                "license": src["license"],
                "cwe_ids": [entry["cwe_id"]],
                "content_hash": _hash(text),
            })
    return chunks


# ---------------------------------------------------------------- main

def main() -> int:
    sources = load_sources()
    OUT.mkdir(parents=True, exist_ok=True)

    cwe_src = sources["mitre-cwe-xml"]
    root = load_cwe_xml(cwe_src)
    weaknesses = {f"CWE-{w.get('ID')}": w for w in root.iterfind(".//c:Weakness", NS)}
    print(f"CWE {cwe_src['version_or_commit']}: {len(weaknesses)} weaknesses in XML")

    top25 = parse_top25(sources["mitre-cwe-top25-2025"])
    top10 = parse_owasp_top10(sources)

    family_cwes = {f"CWE-{c}" for fam in FAMILIES for c in fam["cwe"]}
    unknown_family_cwes = sorted(family_cwes - weaknesses.keys())
    if unknown_family_cwes:
        raise SystemExit(f"catalog references CWE ids missing from MITRE XML: {unknown_family_cwes}")
    missing_sources = sorted({s for fam in FAMILIES for s in fam["sources"]} - sources.keys())
    if missing_sources:
        raise SystemExit(f"catalog references sources that were not downloaded: {missing_sources}")

    wanted = family_cwes | set(top25) | {c for cat in top10.values() for c in cat["mapped_cwes"]}
    entries = {cid: parse_weakness(weaknesses[cid]) for cid in sorted(wanted, key=lambda x: int(x[4:])) if cid in weaknesses}
    skipped = sorted(wanted - entries.keys(), key=lambda x: int(x[4:]))  # categories/views, not weaknesses
    with (OUT / "cwe.jsonl").open("w", encoding="utf-8") as fh:
        for e in entries.values():
            fh.write(json.dumps(e, ensure_ascii=False) + "\n")
    (OUT / "owasp_top10_2025.json").write_text(json.dumps(top10, indent=2, ensure_ascii=False), encoding="utf-8")

    # catalog
    catalog_families = []
    covered = set()
    for fam in FAMILIES:
        cids = [f"CWE-{c}" for c in fam["cwe"]]
        covered |= set(cids)
        owasp = sorted(code for code, cat in top10.items() if set(cids) & set(cat["mapped_cwes"]))
        catalog_families.append({
            "id": fam["id"],
            "name": fam["name"],
            "support_level": "unsupported" if fam.get("unsupported_reason") else "documented_only",
            "mvp": fam["mvp"],
            "cwe": [{"id": c, "name": entries[c]["name"],
                     "top25_2025_rank": top25.index(c) + 1 if c in top25 else None} for c in cids],
            "owasp_top10_2025": owasp,
            "knowledge_sources": fam["sources"],
            "knowledge_card": (f"data/knowledge_cards/{fam['id']}.yaml"
                               if (DATA / "knowledge_cards" / f"{fam['id']}.yaml").exists() else None),
            "detector": None,
            "verifier": None,
            **({"unsupported_reason": fam["unsupported_reason"]} if fam.get("unsupported_reason") else {}),
        })
    catalog = {
        "schema_version": 1,
        "note": ("support_level becomes 'implemented' only when a detector and evaluation exist for the "
                 "family. Being listed here does not mean the agent reviewed for this family."),
        "cwe_release": cwe_src["version_or_commit"],
        "top25_2025": [{"rank": i + 1, "id": c, "name": entries[c]["name"],
                        "family": next((f["id"] for f in FAMILIES if int(c[4:]) in f["cwe"]), None)}
                       for i, c in enumerate(top25)],
        "owasp_top10_2025": {k: {"title": v["title"], "mapped_cwe_count": len(v["mapped_cwes"])}
                             for k, v in top10.items()},
        "families": catalog_families,
    }
    (DATA / "security_catalog.yaml").write_text(
        yaml.safe_dump(catalog, sort_keys=False, allow_unicode=True, width=110), encoding="utf-8")

    # chunks
    cwe_by_source: dict[str, list[str]] = {}
    for fam in FAMILIES:
        for s in fam["sources"]:
            cwe_by_source.setdefault(s, [])
            cwe_by_source[s] = sorted(set(cwe_by_source[s]) | {f"CWE-{c}" for c in fam["cwe"]},
                                      key=lambda x: int(x[4:]))
    for code, cat in top10.items():
        cwe_by_source[cat["source_id"]] = cat["mapped_cwes"]

    chunks: list[dict] = []
    for e in entries.values():
        chunks.extend(chunk_cwe(e, cwe_src))
    for sid, src in sources.items():
        if src["kind"] in ("guidance", "documentation", "ranking") and not sid.startswith("mitre-"):
            chunks.extend(chunk_source(src, cwe_by_source))

    seen, unique = set(), []
    for c in chunks:
        if c["content_hash"] in seen:
            continue
        seen.add(c["content_hash"])
        unique.append(c)
    with (OUT / "chunks.jsonl").open("w", encoding="utf-8") as fh:
        for c in unique:
            fh.write(json.dumps(c, ensure_ascii=False) + "\n")

    top25_uncovered = [c for c in top25 if c not in covered]
    print(f"CWE entries: {len(entries)} (skipped non-weakness ids: {len(skipped)})")
    print(f"OWASP Top 10:2025 categories: {len(top10)}")
    print(f"families: {len(FAMILIES)}  (mvp: {sum(1 for f in FAMILIES if f['mvp'] is True)})")
    print(f"Top 25 not covered by a family: {top25_uncovered or 'none'}")
    print(f"chunks: {len(unique)} (removed duplicates: {len(chunks) - len(unique)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
