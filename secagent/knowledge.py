"""Lexical retrieval over the local knowledge index (SQLite FTS5, BM25)."""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB = ROOT / "data" / "index" / "knowledge.sqlite"

# title, text, cwe_ids weights for bm25()
BM25_WEIGHTS = (4.0, 1.0, 2.0)


def fts_query(text: str) -> str:
    # Identifiers like os.path.join / shell=True become plain tokens; OR them so BM25 ranks by overlap.
    tokens = [t for t in re.findall(r"[A-Za-z0-9]+", text) if len(t) > 1]
    return " OR ".join(f'"{t}"' for t in dict.fromkeys(tokens))


def search(query: str, k: int = 5, cwe: str | None = None, db: Path = DEFAULT_DB) -> list[dict]:
    if not db.exists():
        raise FileNotFoundError(f"knowledge index not built: {db} (run scripts/build_index.py)")
    q = fts_query(query)
    if not q:
        return []
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    sql = (f"SELECT c.id, c.source_id, c.title, c.text, c.cwe_ids, c.source_url, c.version, c.license, "
           f"bm25(chunk_fts, {', '.join(map(str, BM25_WEIGHTS))}) AS score "
           "FROM chunk_fts JOIN chunk c ON c.rowid = chunk_fts.rowid WHERE chunk_fts MATCH ?")
    args: list = [q]
    if cwe:
        sql += " AND (' ' || c.cwe_ids || ' ') LIKE ?"
        args.append(f"% {cwe} %")
    sql += " ORDER BY score LIMIT ?"
    args.append(k)
    try:
        return [dict(r) for r in con.execute(sql, args)]
    finally:
        con.close()
