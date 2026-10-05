# "Other frameworks" test-set protocol (pre-declared, for v5)

Written 2026-10-05, **before any v5 code was written and before any system
was run on this data**. Only the aggregate counts below were computed; the
target code and the individual ground-truth entries have not been opened.
Purpose: the Django run (`docs/experiments.md#t13`) was negative, and the
Django set is now seen data. This is the last untouched Python data in the
benchmark.

## Data

RealVuln at the same pinned commit as the other three subsets
(`7a710251f55c…`, still the benchmark's latest). **All five Python targets
that are not Flask, FastAPI or Django**: `dsvpwa`, `dsvw`, `vulnpy` (no
framework), `dvpwa` (aiohttp), `vulnerable-tornado-app` (tornado). Fetched
with `scripts/fetch_realvuln.py --framework other --out eval/realvuln_other`;
frozen in `eval/realvuln_other/FROZEN.json` (combined SHA-256
`398162f16c5f…`). Same hint removal as before.

Scope: entries in the three MVP families — **44 entries: 27 vulnerable, 17
traps** (SQLi 10 / 15, path traversal 13 / 2, IDOR 4 / 0).

**This set is small.** With 27 vulnerable entries a recall interval is about
±0.18 wide; only large differences can be shown. It is an honest test of one
thing the Django run exposed — whether the agent still works when the
framework is one it has no rules for — and little else. IDOR (4 entries) is
not assessable here.

## What v5 is allowed to be

Changes that follow from the T13 analysis, developed on the four seen sets
(holdout, Flask, FastAPI, Django) and the dev targets, never on this set:

1. Injection-family recall of the sweep on unfamiliar code (v4 found 3 of 18
   SQL injections and 1 of 36 path traversals on Django; one prompt per file
   found 6 and 13).
2. Framework-independent coverage: reading order and budget must not depend
   on a framework's file layout.
3. Smaller fixes to the authorization analysis found on Django (for example a
   gate helper that returns a boolean).

No framework-specific code for aiohttp, tornado or `http.server` may be
written.

## Matching rule and metrics

Identical to `docs/realvuln_protocol.md` (family-level CWE match, same file,
lines ±10, one-to-one, traps count as FP, in-scope unmatched findings count as
FP). Precision, recall, F1 with 95% Wilson intervals, per family and micro.

## Claim (stated before the run)

**Primary:** `agent_v5` reaches at least the single-shot baseline's F1 on this
set (the Django run failed exactly this). **Secondary:** `agent_v5` F1 ≥
`agent_v4` F1. Both are comparisons of point estimates on 44 entries; the
intervals will overlap and the write-up must say so.

## Systems

| Id | Status when this protocol was written |
|---|---|
| `semgrep`, `single_shot` | existing baselines |
| `agent_v2`, `agent_v3`, `agent_v4` | existing, frozen |
| `agent_v5` | to be built; frozen (code hash recorded here) before any system is run on this set |
| v5 ablations | declared together with the v5 freeze |

Each system is run on this set **once**, and **no system is run here before
the v5 freeze** (unlike the Django run, deviation 1 there).

## Frozen code

Recorded 2026-10-05, **before any system was run on this set**.

- v5 = commit `3fada2b`; `secagent/*.py` code hash **`a95b3f6387e20904`**
  (`secagent.evaluate._code_hash()`, LF line endings as checked out).
- Primary system: **`agent_v5`** = v4 plus
  1. a deterministic injection-sink scan (`secagent/sinks.py`): SQL text built
     from values, query filters passed to a document database, file
     operations on computed paths; the value is followed back inside the
     function (request-like expression, entry-point parameter, parameter,
     or neither); sinks and sources are Python-level words, no framework
     code;
  2. seeds with unambiguous static evidence (request value reaches the
     operation, nothing in the function that could be a control) are
     accepted without the verifier; the others go to the verifier with the
     whole function and the scan's facts;
  3. authorization: a helper that returns whether a request credential equals
     a secret is authentication; file-local consistency rule for missing
     authentication. Both behind a flag, so `agent_v4` is unchanged (checked:
     its deterministic pass reproduces the Django run exactly).
- Ablations, declared now: `seeds_v5_only` (both deterministic passes, no
  model) and `sinks_v5_only` (the sink scan alone).
- Dev numbers at the time of the freeze (seen data, the scan was written from
  them - not a result):

  | Dev set | best earlier agent | single-shot | v5 draft 2 (`dd75e5e1`) |
  |---|---|---|---|
  | Holdout (48) | - | F1 0.52 | F1 0.85 (17 TP / 1 FP) |
  | Flask (130) | F1 0.51 (v3) | F1 0.41 | F1 0.57 (41 TP / 12 FP) |
  | Django (277) | F1 0.10 (v4) | F1 0.18 | F1 0.31 (47 TP / 49 FP) |

  Draft 1 lost 10 of 18 Django SQL seeds in the verifier (Mongo filters
  claimed as "SQL injection"; renamed). Draft 2 lost 12 of 31 true Django
  path seeds in the verifier for one false one, which led to point 2 above.
  The frozen code (point 2 added) has **not** been run with the model on any
  set; its dev re-run is done after the run on this set. FastAPI was not
  re-run with any v5 draft. On the seen sets the group of seeds that now skips
  the verifier scored SQL 50 TP / 1 FP and path traversal 74 TP / 22 FP under
  the declared matching rule - numbers the rules were tuned on.
- No further tuning: the code above is what is judged here.

## Deviations

1. The v5 work commits and this protocol were written on 2026-10-05 from
   16:05 (+05:00, the protocol commit), but pushes failed (credential prompt) until 21:20;
   GitHub therefore shows them arriving together, shortly before the freeze.
   The local commit timestamps record the order (protocol `38d4c28` first).
   Everything was pushed before any system ran on this set.
