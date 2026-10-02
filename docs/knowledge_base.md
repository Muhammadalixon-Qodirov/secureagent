# Knowledge base

The agent's security knowledge lives outside the model weights, in a local,
versioned corpus that is retrieved at review time (RAG). This document records
what was collected, why, and what is known to be weak.

## Why retrieval, not fine-tuning (for now)

| | Retrieval (chosen first) | Fine-tuning (later experiment) |
|---|---|---|
| Citations | every finding can point to a chunk id + source URL/version | model cannot say where knowledge came from |
| Updating | rebuild the index | retrain |
| Hardware | runs on the dev machine (RTX 3050, 8 GB VRAM) | QLoRA on 7B is possible but tight |
| Data needed | hundreds of good chunks | thousands of labelled examples |

Fine-tuning is only worth trying after a measured baseline shows a gap that
retrieval cannot close.

## Pipeline

```
scripts/fetch_sources.py   -> data/raw/**, data/sources.jsonl          (network, run once)
scripts/build_knowledge.py -> data/knowledge/{cwe.jsonl, owasp_top10_2025.json, chunks.jsonl}
                              data/security_catalog.yaml
scripts/validate_cards.py  -> checks data/knowledge_cards/*.yaml against the corpus
scripts/build_index.py     -> data/index/knowledge.sqlite              (SQLite FTS5, BM25)
```

Rebuild from scratch:

```
pip install -r requirements.txt
python scripts/fetch_sources.py
python scripts/build_knowledge.py
python scripts/validate_cards.py
python scripts/build_index.py
python scripts/build_index.py --query "send_file os.path.join filename" --cwe CWE-22
```

After the fetch step everything runs offline.

## What was collected (49 sources)

| Source | Version / pin | License | Used for |
|---|---|---|---|
| MITRE CWE XML | CWE v4.20 | MITRE CWE Terms of Use | weakness definitions, consequences, mitigations, detection methods |
| CWE Top 25 | 2025 list | MITRE CWE Terms of Use | catalog ranking |
| OWASP Top 10 | 2025 (10 category pages) | CC BY-SA 4.0 | category → mapped CWE ids |
| OWASP Cheat Sheet Series (23 sheets) | git commit `84dfd96` | CC BY-SA 4.0 | defensive guidance per family |
| Python stdlib docs (7 modules) | CPython `3.13` commit `855c740` | PSF-2.0 | sqlite3, subprocess, pickle, os.path, tempfile, secrets, hmac |
| Flask, Flask-Login, Werkzeug, Jinja, SQLAlchemy docs | "stable" HTML (not pinned) | BSD-3 / MIT | framework behaviour (autoescape, safe_join, login_required, text()) |
| OWASP Path Traversal page | community page | CC BY-SA 4.0 | path traversal guidance |

Every file is listed in `data/sources.jsonl` with URL, retrieval time, SHA-256
and license. Every chunk carries `source_url`, `source_version_or_commit`,
`retrieved_at`, `license`, `cwe_ids` and `content_hash`.

**Deliberately excluded:** payload / filter-evasion catalogues (e.g. the OWASP
XSS Filter Evasion sheet). The agent's job is to recognise unsafe code, its
controls and its fix; attack strings do not help with that and do not belong in
a review tool's context.

## Catalog

`data/security_catalog.yaml` — 20 vulnerability families covering all of the
2025 CWE Top 25 and mapped to OWASP Top 10:2025.

- `support_level` is `documented_only` for every family today. It becomes
  `implemented` only when a detector **and** an evaluation exist. Being listed
  does not mean the agent reviewed for the family.
- `memory_safety` (CWE-787, 416, 125, 120, 121, 122, 476) is `unsupported`: the
  MVP reviews Python/Flask code.
- The build fails if any catalog CWE id is missing from the MITRE XML, so the
  catalog cannot contain invented ids.

## Knowledge cards

Hand-written, one per family the MVP targets: `sql_injection`,
`path_traversal`, `authorization_idor` (MVP) and `os_command_injection`, `xss`
(stretch). Each card lists untrusted sources, sinks, effective controls,
ineffective/partial controls, false-positive patterns, review questions, a
synthetic vulnerable/fixed example, a lab verification idea, remediation and
regression tests.

Rule: every claim has `refs` (chunk ids) or is explicitly marked
`basis: reviewer_reasoning`. `validate_cards.py` enforces this.

Current state: 5 cards, 71 refs, 56 sourced claims, 14 reviewer-reasoning
claims, all refs resolve.

Examples of facts the cards rely on, each verified in the source text:

- `os.path.join` ignores all previous segments when a later segment is absolute
  (`doc-python-os_path#000.5`).
- `@login_required` only ensures the user is logged in and authenticated
  (`doc-flask_login#020.0`) — it says nothing about object ownership.
- Flask autoescapes `.html/.htm/.xml/.xhtml/.svg` templates and
  `render_template_string`, while plain Jinja does not autoescape by default
  (`doc-flask_templating#001.0`, `doc-jinja_autoescape#003.0`).
- Jinja escaping does not protect unquoted attributes or `javascript:` URLs in
  `href` (`doc-flask_web_security#002.0`).
- `safe_join` considers only the path name, not symlinks
  (`doc-werkzeug_safe_join#004.1`).

## Retrieval sanity check (dev queries, not an evaluation)

Five queries written while building the index; expected family = the card's
family.

| Query | Top-1 | Expected family in top-5 |
|---|---|---|
| `send_file os.path.join filename from request.args` | path traversal card | yes |
| `subprocess.run shell=True with user input` | subprocess docs (older API section) | yes |
| `login_required get invoice by id without owner check` | IDOR card | yes |
| `f-string SELECT cursor.execute request.args` | SQL injection card | yes |
| `Markup safe filter on user comment` | **LLM prompt-injection cheat sheet (wrong)** | yes |

With a CWE filter (`--cwe CWE-79`) the wrong top-1 disappears. The agent will
normally query with the family of its current hypothesis, so it can use the
filter.

Observed weaknesses to measure properly later:

- The most relevant official chunks are not always ranked first — e.g.
  subprocess "Security Considerations" and Flask's XSS section did not reach
  the top 5 for the queries above.
- Lexical retrieval matches words, not meaning; paraphrased queries will miss.

These are 5 hand-written queries, so they show the index works, not how well.
A proper retrieval evaluation (labelled queries, recall@k, with/without CWE
filter, BM25 vs. embeddings) belongs to the evaluation phase.

## Known limitations

- Chunk ids are positional (`source#section.part`). Pinned sources rebuild
  identically, but the unpinned framework HTML pages may change; the validator
  then reports broken refs, but a ref could also silently point at a shifted
  section. Storing the chunk `content_hash` next to each ref would close this.
- CWE "Demonstrative Examples" and "Observed Examples" (CVE references) are not
  ingested yet; most examples are C/Java.
- Card `reviewer_reasoning` claims (14) are the author's analysis, not
  source-backed; they are labelled so they can be reviewed.
- Large API pages are filtered by keyword before chunking; a relevant section
  without any keyword is dropped.
