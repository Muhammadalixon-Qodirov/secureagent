# Evaluation protocol (pre-declared)

Written and frozen on 2026-10-02 **before any agent, baseline or ablation was run
on the evaluation data**. Holdout files are fixed by SHA-256 in
`eval/holdout/FROZEN.json` (combined hash
`aaa26b9746a77249abf2e3154e5a33478e959551c525d8003997681cd9881e0a`). Any later
change to labels or rules is listed in "Deviations" below with its reason;
nothing is changed silently.

## Data

**1. Synthetic holdout (primary)** — `eval/holdout/apps/` (10 small Flask apps,
13 files), ground truth in `eval/holdout/manifest.yaml`: 48 cases.

| Family | Vulnerable | Safe look-alike |
|---|---|---|
| SQL injection (CWE-89) | 7 | 7 |
| Path traversal (CWE-22 family) | 6 | 8 |
| Authorization / IDOR (CWE-639/862/863) | 9 | 11 |

Variety on purpose: helpers in another module, SQLAlchemy ORM and `text()`,
Blueprints with tenant ids, a custom ownership decorator, `before_request`
login, `pathlib`, `safe_join`/`secure_filename`/`send_from_directory`, an
allow-listed `ORDER BY`, placeholder-only f-strings, a `startswith` prefix check
without separator.

Known weaknesses of this set, stated up front: it is small (CIs will be wide),
it was written by the same author as the agent, and some patterns resemble the
synthetic examples in the knowledge cards. It was written after the agent's
development target (`targets/demo_app`), and no controller or prompt change is
made after looking at holdout results.

**2. RealVuln, Flask subset (secondary, later)** — public, independently
labelled, but likely seen in model training data. Scored with RealVuln's own
rule (same file, acceptable CWE, ±10 lines), MVP families only.

## Unit of review

Each app directory is one review: it is the agent's only authorized root. The
manifest and this document are outside it.

## Matching rule

- A finding's family comes from its `cwe_id` via the manifest's `families`
  map. Findings with a CWE outside the three MVP families (or none) are
  **out of scope**: reported separately, not counted as FP or TP.
- A finding matches a case if the family is equal, the file is one of the
  case's loci files, and any evidence line range overlaps the line span of a
  locus function (span = first decorator line … last line, from the AST),
  widened by ±2 lines.
- Matching is one-to-one, greedily in finding order. A second finding on an
  already matched case is a **duplicate** (reported, not counted).
- Vulnerable case matched → TP. Vulnerable case unmatched → FN.
  Safe case matched → FP (look-alike). In-scope finding matching no case → FP
  (unmatched).

## Metrics

Per family and micro-averaged over the three families:
precision = TP / (TP + FP), recall = TP / (TP + FN), F1, look-alike FP rate =
matched safe cases / safe cases. 95% Wilson intervals for precision and recall.
Also: wall-clock time per app, model calls, tool calls, invalid replies, and
controller interventions (rejected findings, rebound evidence, verifier
verdicts).

## Systems compared (same model `qwen3:8b`, same machine, `num_ctx` 8192)

| Id | System |
|---|---|
| `semgrep` | project Semgrep taint rules only (no model) |
| `single_shot` | one model call per app with all source files inline, asked for findings in the three families; no tools, no controller checks beyond JSON schema |
| `agent` | full agent: one pass per family, card review questions, evidence rules, verifier |
| `agent_no_verify` | ablation: verifier off |
| `agent_single_pass` | ablation: one open-ended pass |
| `agent_no_cards` | ablation: per-family passes without the card's review questions (knowledge ablation) |

Decoding is greedy (temperature 0), so a configuration is run once; repeated
runs at temperature 0 would measure nothing. Run-to-run variance at temperature
> 0 is a separate, optional experiment.

## Deviations

1. **Runner made resumable (procedural, no scoring change).** The first batch
   was stopped by the 30-minute background-job limit after `agent` (complete)
   and 4/10 apps of `agent_no_verify`. The runner now stores each finished app
   as `result.json` and skips it on restart; an interrupted app directory is
   deleted and that app re-run from scratch. Finished apps from the first batch
   were back-filled from their `final.json` (same findings the scorer had
   used); re-scoring `agent` from the cache reproduced its numbers exactly.
2. **Temperature 0 is not deterministic here.** Protocol assumed one run per
   configuration. Investigation is identical in `agent` and
   `agent_no_verify` until the verifier runs, yet on `media` the first had a
   look-alike FP (M1) that the second did not produce. Likely cause: Ollama
   prefix-cache reuse / GPU floating-point order. Run-to-run variation is
   therefore reported, not assumed away: the primary configuration(s) are
   repeated and the spread is shown. No system change is involved.
3. **Diagnosis after seeing `agent` results (analysis only).** The trace shows
   the verifier withdrew 10 of 13 proposed findings, in several cases with a
   reason that describes the vulnerability ("… classic SQL injection. However
   …"), and was misled by partially parameterised queries. The verifier is
   **not** changed for this holdout. Any later verifier change is labelled
   "post-holdout" and must be judged on independent data (RealVuln), because
   this holdout can no longer test it fairly.
4. **Baseline parsing bug fixed (fairness, re-scored from saved replies).**
   Ollama's grammar does not enforce the JSON-schema regex `pattern`; the
   single-shot model wrote `"cwe_id": "89"` in 3/10 apps and strict validation
   discarded those whole replies, including real findings (B1, C1, O1). Bare
   CWE numbers are now normalised to `CWE-<n>` before validation, and the
   single-shot baseline was re-scored from its saved `reply.json` files — no
   new model calls. First-run result: P 0.41 / R 0.32; corrected: P 0.50 /
   R 0.55. The same pattern caused 1 of 439 agent replies to be invalid.
5. **Additional configuration (not pre-declared):** `agent_no_verify_no_cards`,
   to separate the effect of the card questions from the verifier's, because
   the pre-declared `agent_no_cards` keeps the verifier on and the verifier
   dominated the result.
