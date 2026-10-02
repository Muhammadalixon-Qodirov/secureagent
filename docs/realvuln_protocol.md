# RealVuln evaluation protocol (pre-declared)

Written 2026-10-02 **before any system was run on this data**, after the
synthetic-holdout results were known. Its job: judge the post-holdout changes
(agent v2) on data that played no part in designing them.

## Data

RealVuln benchmark (`kolega-ai/Real-Vuln-Benchmark`, Apache-2.0) at commit
`7a710251f55c…`, **all 15 Flask targets**, each fetched at the commit pinned
in its ground truth (`scripts/fetch_realvuln.py`). Frozen in
`eval/realvuln/FROZEN.json` (combined SHA-256 `87326600bbce…`).

Scope: ground-truth entries whose primary or acceptable CWE is in the three
MVP families — **90 vulnerable entries and 40 traps** (safe code that looks
vulnerable). Other entries (XSS, code injection, …) are ignored, and so are
findings outside the three families.

Hint removal, applied identically for all systems: files that describe the
bugs (README, `*.md`, `*.rst`, `solutions/`, `docs/`, walkthroughs) are deleted;
Python `#` comments are blanked keeping every line, so ground-truth line
numbers stay valid. All ground-truth files survived this step.

**Known limitation:** these are well-known teaching apps (DVGA, VAmPI, vulpy,
…). The model has very likely seen them during training; absolute numbers
may be inflated by memorisation. Comparisons between systems that use the same
model are less affected.

## Matching rule

- A finding is in scope if its CWE belongs to one of the three families
  (same family map as the holdout).
- It matches a ground-truth entry if the file is the same, its family equals
  the family of the entry's primary or acceptable CWEs, and an evidence line
  range overlaps the entry's lines ±10 (RealVuln's line tolerance). The
  family-level CWE match is more lenient than RealVuln's per-CWE list; it is
  applied to every system alike.
- One-to-one, greedy in finding order; extra findings on a matched entry are
  duplicates (not counted). Vulnerable entry matched → TP; unmatched → FN.
  Trap matched → FP. In-scope finding matching nothing → FP.

## Metrics

Precision, recall, F1 (micro and per family) with 95% Wilson intervals,
time per target, model and tool calls.

## Systems

| Id | Why |
|---|---|
| `semgrep` | static baseline |
| `single_shot` | model reads code directly; large apps split into ≤ ~5K-token batches of whole files |
| `agent_v1` | best v1 configuration on the holdout by F1 among agent configurations: **agent without verifier** (fixed before any RealVuln run) |
| `agent_v2` | post-holdout version (design fixed in `docs/experiments.md#t07`) |

The v2 code is completed and frozen (git-free: SHA-256 of `secagent/*.py`
recorded at run time in each result) before its first RealVuln run; no change
is made after seeing RealVuln results. If a v2 change is needed after that, it
is reported as a further deviation with both numbers.

## Frozen code

`secagent/*.py` SHA-256 (first 16 hex, as recorded in every v2 result): `c06492366d601eb6`, frozen 2026-10-02T15:49:23+00:00 before the first RealVuln run.

## Deviations

1. **CLI wiring changed after the RealVuln runs** (`secagent/__main__.py`: v2 became the
   default `review` mode). The sweep, verifier, tools and evaluation code that produced the
   results are unchanged, but the combined `secagent/*.py` hash no longer equals the frozen
   `c06492366d601eb6`; every result file records the hash it was produced with.
