"""Build the local lexical retrieval index (SQLite FTS5, BM25 ranking).

Indexes data/knowledge/chunks.jsonl plus the knowledge cards in
data/knowledge_cards (as project-authored chunks). This is lexical retrieval,
not embeddings / vector search.

    python scripts/build_index.py
    python scripts/build_index.py --query "send_file os.path.join filename" [--cwe CWE-22] [-k 5]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from secagent.knowledge import search  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
CHUNKS = ROOT / "data" / "knowledge" / "chunks.jsonl"
CARDS = ROOT / "data" / "knowledge_cards"
DB = ROOT / "data" / "index" / "knowledge.sqlite"

def card_chunks() -> list[dict]:
    """Split each card into a few retrievable sections."""
    out = []
    for path in sorted(CARDS.glob("*.yaml")):
        card = yaml.safe_load(path.read_text(encoding="utf-8"))
        cwes = [card["cwe"]["primary"], *card["cwe"].get("related", [])]
        sections = {
            "overview": {k: card.get(k) for k in ("title", "cwe", "stack", "untrusted_sources")},
            "sinks": {k: card.get(k) for k in ("sinks", "protected_operations") if card.get(k)},
            "controls": {k: card.get(k) for k in ("effective_controls", "ineffective_or_partial_controls")},
            "false_positives": {k: card.get(k) for k in ("false_positive_patterns", "review_questions")},
            "example_and_fix": {k: card.get(k) for k in ("example", "remediation", "regression_tests", "verification")},
        }
        for name, body in sections.items():
            text = yaml.safe_dump(body, sort_keys=False, allow_unicode=True, width=110).strip()
            out.append({
                "id": f"card-{card['id']}#{name}",
                "source_id": f"card-{card['id']}",
                "title": f"Knowledge card: {card['title']} — {name.replace('_', ' ')}",
                "text": text,
                "source_url": None,
                "source_version_or_commit": hashlib.sha256(path.read_bytes()).hexdigest()[:12],
                "retrieved_at": None,
                "license": "project-authored (cites sources in refs)",
                "cwe_ids": cwes,
                "content_hash": hashlib.sha256(text.encode()).hexdigest(),
            })
    return out


def build() -> None:
    rows = [json.loads(l) for l in CHUNKS.read_text(encoding="utf-8").splitlines() if l.strip()]
    rows += card_chunks()
    DB.parent.mkdir(parents=True, exist_ok=True)
    if DB.exists():
        DB.unlink()
    con = sqlite3.connect(DB)
    con.executescript("""
        CREATE TABLE chunk (
            rowid INTEGER PRIMARY KEY,
            id TEXT UNIQUE NOT NULL,
            source_id TEXT NOT NULL,
            title TEXT NOT NULL,
            text TEXT NOT NULL,
            cwe_ids TEXT NOT NULL,
            source_url TEXT,
            version TEXT,
            retrieved_at TEXT,
            license TEXT,
            content_hash TEXT NOT NULL
        );
        CREATE VIRTUAL TABLE chunk_fts USING fts5(
            title, text, cwe_ids, content='chunk', content_rowid='rowid',
            tokenize='porter unicode61'
        );
    """)
    con.executemany(
        "INSERT INTO chunk (id, source_id, title, text, cwe_ids, source_url, version, retrieved_at, license, content_hash)"
        " VALUES (?,?,?,?,?,?,?,?,?,?)",
        [(r["id"], r["source_id"], r["title"], r["text"], " ".join(r["cwe_ids"]), r["source_url"],
          r["source_version_or_commit"], r["retrieved_at"], r["license"], r["content_hash"]) for r in rows])
    con.execute("INSERT INTO chunk_fts (rowid, title, text, cwe_ids) SELECT rowid, title, text, cwe_ids FROM chunk")
    con.commit()
    n_cards = sum(1 for r in rows if r["source_id"].startswith("card-"))
    print(f"indexed {len(rows)} chunks ({n_cards} from knowledge cards) -> {DB.relative_to(ROOT)}")
    con.close()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--query")
    ap.add_argument("--cwe")
    ap.add_argument("-k", type=int, default=5)
    a = ap.parse_args()
    if a.query is None:
        build()
        return 0
    for r in search(a.query, a.k, a.cwe):
        print(f"{r['score']:8.2f}  {r['id']:58s} {r['title'][:60]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
