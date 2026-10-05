# Django test-set protocol (pre-declared, for v4)

Written 2026-10-03 **before any v4 code was written and before any system was
run on this data**. The author has not opened the target code or read
individual ground-truth entries; only the aggregate counts below were
computed. Purpose: an untouched test for v4, because both earlier RealVuln
subsets (Flask, FastAPI) are now seen data — the v4 idea comes from the
post-hoc analysis of the FastAPI run (`docs/experiments.md#t11`).

## Data

RealVuln benchmark at the same pinned commit as the other two subsets
(`7a710251f55c…`; it is still the benchmark's latest commit, so no newer
Flask/FastAPI targets exist). **All 23 Django targets** (3 human-authored,
20 LLM-generated "seeded" apps). Fetched with
`scripts/fetch_realvuln.py --framework django --out eval/realvuln_django`;
frozen in `eval/realvuln_django/FROZEN.json` (combined SHA-256
`4513830ef294…`). Same hint removal as before (README/markdown/doc files
deleted, Python comments blanked, line numbers kept).

Scope: entries in the three MVP families — **277 entries: 204 vulnerable,
73 traps** (IDOR 150 / 45, path traversal 36 / 7, SQLi 18 / 21).

Why this is a hard, honest test: Django is a framework the agent has never
been run on. Routing lives in `urls.py`, views are functions, class-based
views or DRF viewsets, authorization is expressed with `request.user`,
mixins and `permission_classes`. v1–v3 contain no Django-specific code.

## What v4 is allowed to be

1. **Helper resolution** (the diagnosed FastAPI failure): when a handler
   delegates authorization to a project function, that function's body is
   analysed / shown to the verifier instead of assuming either way.
2. **Django support** in the route and authorization analysis, written
   without access to this set: developed on the Django documentation's
   conventions and on small synthetic Django apps written for the purpose
   (`eval/dev_django/`), plus the three seen sets as regression checks.

Development data for v4: synthetic holdout, RealVuln Flask, RealVuln FastAPI
(all seen), the dev target and the synthetic Django dev apps. Never this set.

## Matching rule and metrics

Identical to `docs/realvuln_protocol.md` (family-level CWE match, same file,
lines ±10, one-to-one, traps count as FP, in-scope unmatched findings count
as FP). Precision, recall, F1 with 95% Wilson intervals, per family and micro.

### Amendment 1 (2026-10-03, before any run on this set): secondary metric

While developing v4 on the FastAPI set it turned out that the family-level
rule counts location matches on entries whose *primary* CWE is not access
control (mass assignment, CORS, business-logic gaps) as IDOR true positives
(`docs/experiments.md`, T11 erratum). The primary metric above stays as
declared, for comparability with the earlier runs. Added, and computed by
`scripts/core_split.py` for every system:

- IDOR true positives split into **core** (primary CWE in 639, 862, 863, 284,
  285, 306, 425, 566) and other;
- **core recall** = core true positives / core entries, with a Wilson
  interval; **core precision** = core TP / (core TP + IDOR false positives).

Aggregate counts on this set (the only thing read from the ground truth):
150 IDOR-family vulnerable entries, **59 core**.

The claim v4 is built to support is about the secondary metric: *fewer IDOR
false positives than v2/v3 without losing core recall*.

## Systems

| Id | Status when this protocol was written |
|---|---|
| `semgrep`, `single_shot` | existing baselines |
| `agent_v2`, `agent_v3` | existing; v3 has no Django route support, so on this set it is expected to behave like v2 |
| `agent_v4` | to be built; frozen (code hash recorded here) before its first run on this set |
| v4 ablations | declared together with the v4 freeze |

Each system is run on this set **once**. If time limits force a subset of
apps, the subset is chosen before any run (alphabetical order, first N) and
stated under Deviations.

## Frozen code

Recorded 2026-10-05, **before `agent_v4` or any v4 ablation was run on this
set**.

- v4 = commit `613b32a`; `secagent/*.py` code hash **`0b17455e08bfb8a9`**
  (`secagent.evaluate._code_hash()`, LF line endings as checked out).
- Primary system: **`agent_v4`** (v3 with injection hardening + helper
  resolution + Django views + helper bodies shown to the verifier + 80-window
  budget, handler and sink files first).
- Ablation, declared now: `authz_v4_only` (deterministic seeds only, no model).
- Dev numbers at the time of the freeze (seen data, not a result):
  - Three v4 drafts were run in full on the dev sets. The last one (commit
    `a666e4f`, kept as `agent_v4_draft3`) gave, on FastAPI, IDOR false
    positives 270 -> 101 against v3 **and core true positives 23 -> 10** -
    i.e. it failed the claim on dev. On Flask: 31 TP / 13 FP (v3: 33 / 7).
  - Diagnosis of the lost FastAPI findings: audit/logging helpers
    (`AuditLog(actor_id=user.id)`) were classified as owner checks, so every
    handler that wrote an audit row counted as scoped and was never seeded.
    Fixed in `613b32a` (one regular expression, with a unit test).
  - After the fix only the deterministic pass was re-run on dev before the
    freeze: `authz_v4_only` FastAPI 13 core TP / 66 IDOR FP (v3's
    `authz_only`: 16 / 223), Flask 8 TP / 2 FP. The full `agent_v4` dev
    re-run of the frozen code is done **after** the run on this set and
    cannot change the code.
- No further tuning: whatever the dev re-run shows, the code above is what is
  judged here.

## Deviations

1. **Baselines were started before the v4 freeze.** `semgrep`, `single_shot`,
   `agent_v2`, `agent_v3` were launched on this set on 2026-10-05 while the
   last v4 bug was being diagnosed on the FastAPI dev set (to use the GPU
   time). When the fix was written and the freeze recorded, `semgrep` had
   finished and the three model systems had not completed a single app; no
   score, finding or log line from this set had been read. The fix touches
   only code behind `resolve=True`, which none of the baselines use.
2. Background jobs on this machine are stopped after two hours, so runs are
   resumed (`evaluate` skips apps that already have a `result.json`; an app
   interrupted midway is run again from scratch). Each app still has exactly
   one completed run per system.
