# FastAPI test-set protocol (pre-declared, for v3)

Written 2026-10-03 **before any v3 code was written and before any system was
run on this data**. The author has not opened the target code. Purpose: an
independent test for the next version (v3: authorization/IDOR work, ML
filtering), whose development uses the earlier data (synthetic holdout,
RealVuln Flask) as development sets.

## Data

RealVuln benchmark at the same pinned commit as the Flask set
(`7a710251f55c…`), **all 23 FastAPI targets** (3 human-authored, 20
LLM-generated "seeded" apps). Fetched with
`scripts/fetch_realvuln.py --framework fastapi --out eval/realvuln_fastapi`;
frozen in `eval/realvuln_fastapi/FROZEN.json` (combined SHA-256
`e17d17c13fd9…`). Same hint removal as the Flask set; all ground-truth files
survived it.

Scope: entries in the three MVP families — **244 entries: 182 vulnerable,
62 traps** (IDOR 125 / 38, path traversal 35 / 11, SQLi 22 / 13).

Differences that make this a real test of generalisation: FastAPI routing
(`@router.get`), dependency-injected authentication (`Depends(...)`),
Pydantic models, and apps written by other LLMs rather than classic teaching
apps (lower memorisation risk, but seeded bugs may be stylised).

## Matching rule and metrics

Identical to `docs/realvuln_protocol.md` (family-level CWE match, same file,
lines ±10, one-to-one, traps count as FP, in-scope unmatched findings count as
FP). Precision, recall, F1 with 95% Wilson intervals, per family and micro.

## Systems

| Id | Status when this protocol was written |
|---|---|
| `semgrep`, `single_shot` | existing baselines |
| `agent_v2` | existing, unchanged since its RealVuln run |
| `agent_v3` | to be built; must be frozen (code hash recorded here) before its first run on this set |
| v3 ablations | declared together with the v3 freeze, before running |

Each system is run on this set **once**. Development of v3 may use the
synthetic holdout, the RealVuln Flask set (preferably with leave-one-app-out
cross-validation for anything learned) and the dev target — never this set.

## Frozen code

Recorded 2026-10-03, after v3 development on the dev sets
(`docs/experiments.md#t08`) and **before any system was run on this set**.

- v3 = commit `a910323`; `secagent/*.py` code hash **`a4a4667ed531acd6`**
  (`secagent.evaluate._code_hash()`, LF line endings as checked out).
- Primary system: **`agent_v3`** (v2 sweep + deterministic authorization
  seeds + verifier v2). Chosen on dev data: RealVuln Flask F1 0.51 vs. 0.46
  for v2 (dev numbers — the v3 rules were written after reading that set).
- Ablations, declared now: `agent_v3_no_verify` (verifier off) and
  `authz_only` (deterministic seeds only, no model).
- Not run here: the learned FP filter (negative LOAO result on dev data, not
  adopted).
- Expectations stated before the run: v3 ≥ v2 on IDOR recall; FastAPI's
  `Depends(...)` auth is recognised by `authz.py`, but its behaviour on
  LLM-written apps is unknown. If v3 is worse than v2 on this set, that is
  the result.

Run order: `semgrep`, `single_shot`, `agent_v2`, `agent_v3`,
`agent_v3_no_verify`, `authz_only` — each once, results reported whatever
they are.

## Deviations

(none yet)
