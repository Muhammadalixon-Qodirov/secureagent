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

(to be filled in when v4 is frozen)

## Deviations

(none yet)
