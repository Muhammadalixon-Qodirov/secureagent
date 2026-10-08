# CVE-replay test-set protocol (pre-declared, for v6)

Written 2026-10-07, **before any v6 code was written and before any system
was run on this data**. Purpose: after T14 no unseen Python data is left in
the RealVuln benchmark, so nothing added after v5 could be tested honestly.
This set is built from public advisories instead. Plan: `docs/V6_REJA.md`.

## Data

Source: the public OSV dump for PyPI
(`osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip`; SHA-256 of the
dump used is recorded in each half's `FROZEN.json`). Builder:
`scripts/build_cve_replay.py`. Selection rules, fixed before anything was
fetched:

- advisory **published in 2026**, not withdrawn — after the training data of
  the model used (qwen3:8b), so the fix cannot have been memorised;
- CWE ids map to exactly one of the three families: SQL injection (89, 564,
  943), path traversal (22, 23, 36, 73), authorization (639, 862, 863, 284,
  285, 306);
- exactly one GitHub fix commit in the references, with one parent;
- the commit modifies 1–5 non-test Python files (version files excluded);
  hunks that only edit imports are not locations.

For every advisory two snapshots are stored: the parent of the fix
(**vulnerable**) and the fix (**fixed**). Only the review scope is kept: the
changed files plus the other Python files of their directories, at most 25
files and 250 KB. Python comments are blanked, line numbers kept (as in the
earlier sets). **This is a "directory given" test**: the system is told which
part of a large repository to read. It does not measure finding the place in
a whole repository.

**Split, by repository and before fetching:** first hex digit of
`sha256("owner/repo")` even → dev half, odd → test half. No codebase is in
both. Within a half and family, the first 12 advisories in
`sha256(advisory id)` order that can be built are kept, at most 2 per
repository. Advisories that cannot be built (repository gone, merge commit,
too many files) are listed with the reason in `FROZEN.json`.

The dev half may be read and used for development. **The test half is not
opened**: only its aggregate counts are read until the v6 freeze.

## Matching rule and metrics

Family and location as before (`docs/realvuln_protocol.md`): a finding
matches when it is in the advisory's family, in a changed file, within ±10
lines of a changed hunk (old-side lines on the vulnerable snapshot, new-side
lines on the fixed one).

- **Detected**: a match on the vulnerable snapshot.
- **Still flagged after the fix**: a match on the fixed snapshot.
- **Pair success** (primary): detected and not still flagged. A system that
  flags the place whatever the code says scores zero.
- **Other findings per snapshot**: in-scope findings that match nothing.
  These are *not* called false positives — the code is real and unlabelled
  elsewhere — but a system that produces many of them is noisy.

Rates with 95% Wilson intervals (`scripts/cve_pairs.py`).

## Known limits, stated in advance

- The lines a fix changes are not always the lines where the flaw is (a
  check added in a caller, a helper introduced elsewhere). Some true findings
  will not match, for every system alike.
- A fix that adds a check near the sink leaves the sink in place; a system
  that cannot see the new check keeps flagging it. That is exactly what pair
  success penalises.
- These are libraries and large applications, not teaching apps: low absolute
  numbers are expected. The set has at most 36 advisories per half, so
  intervals are wide.
- Authorization advisories are heterogeneous (missing permission checks in
  CLIs, agents, admin tools — not only web IDOR).

## Claim (stated before v6 exists)

**Primary:** on the test half, `agent_v6` has pair success at least as high
as `agent_v5`. **Secondary:** at least as high as the single-shot baseline.
Point estimates on at most 36 advisories; the write-up must give the
intervals.

## Systems

| Id | Status when this protocol was written |
|---|---|
| `single_shot` | existing baseline |
| `agent_v5` | existing, frozen (`a95b3f6387e20904` for its code path) |
| `agent_v6` | to be built behind a `v6` flag; frozen (code hash recorded here) before any system runs on the test half |

Each system runs on the test half **once**. No system runs there before the
v6 freeze.

## Frozen data

Built 2026-10-07 from OSV dump `bf70e44df106…` (276 candidate advisories: 148
in dev repositories, 128 in test repositories).

| Half | Advisories | SQLi | Path traversal | Authorization | Repositories | Combined SHA-256 |
|---|---|---|---|---|---|---|
| dev | 28 | 4 | 12 | 12 | 24 | `cd956d07d224980f…` |
| test | 30 | 6 | 12 | 12 | 25 | `caff5c802a70af4e…` |

SQL injection is short of 12 in both halves: every 2026 candidate was tried.
Not built: 23 in dev, 8 in test (fix touches more than five files: 19 and 5;
merge commit: 2 and 2; commit no longer on GitHub: 2 and 1) — listed in each
`FROZEN.json`. Only these counts were read from the test half.

## Frozen code

Recorded 2026-10-08, **before any system was run on the test half**.

- v6 = commit `ea196f2`; `secagent/*.py` code hash **`cfa5001182c3e616`**
  (`secagent.evaluate._code_hash()`, LF line endings as checked out).
- Primary system: **`agent_v6`** = v5 plus, all behind a `v6` flag:
  1. control strength in the sink scan (`secagent/sinks.py`): a sink behind a
     strong control (structural path containment, a single path component,
     SQL identifier quoting) is not reported; one behind a weak control (a
     text test on the path) is reported as bypassable; project functions
     that are themselves a strong path check count as one;
  2. a five-verdict verifier (vulnerable / bypassable / inconclusive /
     protected / safe), attacker framing for authorization claims, and up to
     two rounds in which the verifier names a project function and is shown
     it;
  3. one retry on an unusable model reply; sweep candidates that sit on a
     protected sink are rejected without the model.
  Not part of v6: reachability ordering (step 7 of the plan, dropped).
- Systems to run here, once each: `single_shot`, `agent_v5`, `agent_v6`, and
  the model-free ablations `seeds_v5_only`, `seeds_v6_only`.
- `agent_v5` runs from this same commit; its code path is unchanged by the
  flag (unit tests; identical deterministic output on the four seen sets
  apart from the v6-only branches), but its recorded hash is this commit's,
  not `a95b3f6387e20904`.
- Dev numbers at the freeze (seen data): `docs/V6_REJA.md`. On the dev half
  pair success was 6/28 for v6 against 4/28 for v5 and 2/28 for single-shot;
  intervals overlap almost entirely. The scan's control rules were written
  from three fixes in the dev half.
- No further tuning: the code above is what is judged here.

## Deviations

1. **The freeze was not on GitHub when the test run started.** The machine's
   git credentials stopped working on 2026-10-07 (push asks for a login that
   an unattended session cannot give), so commits `406566d` … `61a325a`,
   including the v6 freeze, existed only locally when the systems were
   started on the test half on 2026-10-08. The order is recorded by the local
   commit timestamps and by the timestamps inside the run results; the
   commits are pushed unchanged as soon as a login is possible. The protocol
   itself and both frozen halves were pushed on 2026-10-07 (`061c457`),
   before any v6 code existed.

## Addendum (2026-10-08): a third half for v7

After T15 the test half is seen data. For v7 (`docs/V7_REJA.md`) a further
half **`test2`** was built with the same rules from advisories in
repositories that neither earlier half uses, one advisory per repository:
**16 advisories** (path traversal 8, authorization 8; no SQL injection
candidates were left), 16 repositories, combined SHA-256
`399901176e3ce672…`. Only these counts were read. 20 candidates could not be
built (reasons in its `FROZEN.json`).

v7 frozen before any run on it: commit `1d8f021`, code hash
**`223a451dd78c7cab`**. Systems, once each: `agent_v5`, `agent_v7`,
`seeds_v7_only`. Stated in advance: sixteen pairs cannot show a difference;
the expectation is only that v7's pair success is not below v5's. The
evidence for v7's purpose (fewer authorization false positives than v6) is on
seen sets and is reported as such.

