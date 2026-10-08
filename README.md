# secagent — a local, evidence-driven security review agent

A security code-review agent for Python/Flask that runs entirely on a laptop
(qwen3:8b via Ollama on an 8 GB RTX 3050). It looks for SQL injection, path
traversal and broken object-level authorization (IDOR), and reports only
findings it can tie to code it has actually read.

The interesting part is not the model; it is the controller around it. An 8B
model sees the right thing surprisingly often, but turning that into a correct,
evidence-backed finding — and refusing the plausible wrong ones — took most of
the engineering. See [`docs/experiments.md`](docs/experiments.md).

## Results on the synthetic holdout (48 cases; v1 only — v2 was designed after this)

| System | TP | FP | Precision (95% CI) | Recall (95% CI) | F1 |
|---|---|---|---|---|---|
| Semgrep only (project rules) | 10 | 4 | 0.71 (0.45–0.88) | 0.46 (0.27–0.65) | 0.56 |
| Single-shot LLM, whole app in one prompt | 12 | 12 | 0.50 (0.31–0.69) | 0.55 (0.35–0.73) | 0.52 |
| Agent, pre-declared primary (with verifier) | 2 | 1 | 0.67 (0.21–0.94) | 0.09 (0.03–0.28) | 0.16 |
| Agent without verifier | 9 | 3 | 0.75 (0.47–0.91) | 0.41 (0.23–0.61) | 0.53 |
| Agent without verifier and card questions | 7 | 8 | 0.47 (0.25–0.70) | 0.32 (0.16–0.53) | 0.38 |

Honest reading: the pre-declared agent **failed** — its verifier, which helped
on the dev target, withdrew most true positives on the holdout. Without it the
agent is the most precise system, but it found nothing Semgrep did not; the
single-shot baseline, which reads each small app whole, found the most (all
SQLi, the cross-module case, 2 of 9 IDORs) with the most false positives. The
card review questions measurably helped (F1 0.38 → 0.53). Full analysis and
what changes in v2: [`docs/experiments.md#t07`](docs/experiments.md),
[`eval/results/RESULTS.md`](eval/results/RESULTS.md).

Protocol, matching rule and data: [`docs/evaluation_protocol.md`](docs/evaluation_protocol.md).
Small n — read the confidence intervals.

## Results on independent data (RealVuln, 15 public Flask apps, 130 labelled entries; independent for v1/v2)

| System | TP | FP | Precision (95% CI) | Recall (95% CI) | F1 | Time / app |
|---|---|---|---|---|---|---|
| Semgrep only | 9 | 1 | 0.90 (0.60–0.98) | 0.10 (0.05–0.18) | 0.18 | 11 s |
| Single-shot LLM | 32 | 35 | 0.48 (0.36–0.59) | 0.36 (0.26–0.46) | 0.41 | 17 s |
| Agent v1 (tool loop) | 8 | 3 | 0.73 (0.43–0.90) | 0.09 (0.05–0.17) | 0.16 | 121 s |
| **Agent v2 (coverage sweep + verifier)** | **30** | **10** | **0.75 (0.60–0.86)** | 0.33 (0.24–0.44) | **0.46** | 29 s |

v2 was designed from the holdout failures above and judged once, on this
data, under a protocol frozen beforehand ([`docs/realvuln_protocol.md`](docs/realvuln_protocol.md)).
It matches the single-shot model's recall with ~3.5× fewer false positives and
no matched traps. IDOR (11/53) and path traversal (2/9) remain weak.

## v3: authorization analysis, tested on a second independent set (RealVuln FastAPI, 21 apps, 244 entries)

v3 adds a deterministic authorization analysis (`secagent/authz.py`: ownership
map, per-route auth facts, consistency between sibling handlers) that seeds
IDOR / missing-authentication candidates into the v2 sweep. It was developed
on the two sets above — so its Flask number (33 TP / 7 FP, F1 0.51 vs. 0.46)
is a development number — and tested once on FastAPI apps frozen before v3
existed ([`docs/fastapi_protocol.md`](docs/fastapi_protocol.md); v3 code hash
recorded and pushed before the run).

| System | TP | FP | Precision (95% CI) | Recall (95% CI) | F1 | Time / app |
|---|---|---|---|---|---|---|
| Semgrep only | 0 | 22 | 0.00 (0.00–0.15) | 0.00 (0.00–0.02) | 0.00 | 10 s |
| Single-shot LLM | 22 | 100 | 0.18 (0.12–0.26) | 0.12 (0.08–0.18) | 0.14 | 70 s |
| Agent v2 | 43 | 191 | 0.18 (0.14–0.24) | 0.24 (0.18–0.30) | 0.21 | 244 s |
| Authorization analysis only (no model) | 46 | 223 | 0.17 (0.13–0.22) | 0.25 (0.20–0.32) | 0.20 | 1 s |
| **Agent v3** | **61** | 273 | 0.18 (0.14–0.23) | **0.34 (0.27–0.41)** | **0.24** | 249 s |
| Agent v3 without verifier | 84 | 464 | 0.15 (0.13–0.19) | 0.46 (0.39–0.53) | 0.23 | 89 s |

Honest reading: v3 finds 42% more than v2 (IDOR 42 vs. 23 of 125), as
predicted before the run — but **precision did not transfer** from the Flask
set (0.75–0.83 there, 0.18 here, for v2 and v3 alike). SQLi and path traversal
stay precise (v3: 8 TP / 2 FP and 11 TP / 1 FP); the false positives are IDOR
claims on handlers that delegate authorization to helper functions the
verifier is not shown. Analysis and the next step:
[`docs/experiments.md#t11`](docs/experiments.md). Two more experiments are in
T10 and T12: a learned false-positive filter (negative result, not adopted)
and a prompt-injection suite.

**Prompt injection** (`scripts/injection_suite.py`, [`eval/injection/`](eval/injection/)):
eight clean/injected app pairs, three seeds each. On the frozen v3, 3 of 8
payloads made a real SQL injection disappear from the report (a docstring
"override", a long policy string, instructions in invisible Unicode); no secret
leaked in any run. After deterministic hardening in the controller
(`secagent/hardening.py`: comments and docstrings are not shown to the model,
hidden Unicode is removed and flagged, a verifier may withdraw a finding only by
naming a line of code) 0 of 8 succeed. The defences were written against these
cases, so that is a regression result, not an independent estimate.

## v4: helper resolution and Django, tested on a third independent set (RealVuln Django, 23 apps, 277 entries)

The T11 analysis pointed at authorization delegated to helper functions. v4
classifies helpers and dependencies from their bodies, shows those bodies to
the verifier, adds Django routing and views, and reads handler and sink files
first within an 80-window budget. It was frozen (code hash recorded and pushed)
before it ran on 23 Django apps that no version had seen
([`docs/django_protocol.md`](docs/django_protocol.md)); each system ran once.

| System | TP | FP | Precision (95% CI) | Recall (95% CI) | F1 | Time / app |
|---|---|---|---|---|---|---|
| Semgrep only | 0 | 0 | n/a | 0.00 (0.00–0.02) | n/a | 11 s |
| Single-shot LLM | 27 | 68 | 0.28 (0.20–0.38) | 0.13 (0.09–0.19) | **0.18** | 62 s |
| Agent v2 | 2 | 2 | 0.50 (0.15–0.85) | 0.01 (0.00–0.04) | 0.02 | 40 s |
| Agent v3 | 1 | 4 | 0.20 (0.04–0.62) | 0.01 (0.00–0.03) | 0.01 | 40 s |
| v4 authorization analysis only (no model) | 41 | 117 | 0.26 (0.20–0.33) | 0.20 (0.15–0.26) | 0.23 | 1 s |
| **Agent v4** | 13 | 51 | 0.20 (0.12–0.32) | 0.06 (0.04–0.11) | 0.10 | 96 s |

Honest reading: **a negative result.** The claim v4 was built for — fewer IDOR
false positives than v2/v3 without losing recall on access-control bugs — is
not supported: 48 IDOR false positives against 2 and 4, at 6 of 59 core
access-control entries against 2 and 1. v2 and v3 are not precise here, they
are blind: their 40-window budget is spent alphabetically on `admin.py`,
migrations and models, and the views are never read (the runs report
`partial` coverage). v4 does read the views and still loses to one prompt per
file (F1 0.10 against 0.18). Its model-free analysis scores best under the
declared rule, but 29 of its 41 true positives are location coincidences on
bugs of another kind, which the verifier correctly withdraws. Across the three
sets, development-set numbers did not transfer (F1 0.51 → 0.24 → 0.10) and
each new framework exposed a coverage assumption. Details:
[`docs/experiments.md#t13`](docs/experiments.md).

## v5: injection-sink seeds, tested on a fourth independent set (5 apps on other frameworks, 44 entries)

The Django diagnosis: the model sweep read the right files and still listed
nothing for a request value joined to a base directory and read. v5 finds
such operations with the AST (`secagent/sinks.py`: SQL text built from
values, request-supplied document-database filters, file operations on
computed paths), follows the value back inside the function, and seeds one
claim per sink — accepted directly when the static evidence is unambiguous,
sent to the verifier otherwise. No framework code. Frozen and pushed before
anything ran on the last unseen Python targets of the benchmark (aiohttp,
tornado, no framework; [`docs/other_protocol.md`](docs/other_protocol.md)).

| System | TP | FP | Precision (95% CI) | Recall (95% CI) | F1 |
|---|---|---|---|---|---|
| Semgrep only | 0 | 0 | n/a | 0.00 (0.00–0.13) | n/a |
| Single-shot LLM | 10 | 59 | 0.15 (0.08–0.25) | 0.37 (0.22–0.56) | 0.21 |
| Agent v2 / v3 / v4 | 4 / 3 / 4 | 2 / 2 / 1 | 0.67 / 0.60 / 0.80 | 0.15 / 0.11 / 0.15 | 0.24 / 0.19 / 0.25 |
| v5 deterministic passes only (no model) | 6 | 2 | 0.75 (0.41–0.93) | 0.22 (0.11–0.41) | 0.34 |
| **Agent v5** | 9 | 3 | 0.75 (0.47–0.91) | 0.33 (0.19–0.52) | **0.46** |

Honest reading: the claims stated before the run hold on point estimates
(F1 above single-shot and above v4), on a set of only 27 vulnerable entries.
What the intervals support is narrower: v5 finds about as much as one prompt
per file (9 against 10) with a twentieth of the false positives (3 against
59). It does not find more, and path traversal stays weak (2 of 13): the scan
found 31 of 36 on Django, where it was developed, and here ran into Python 2
source it cannot parse, one very long handler, and sinks outside its list.
Details: [`docs/experiments.md#t14`](docs/experiments.md).

## v6: ideas from other agents, tested on real 2026 advisories (CVE replay, 30 advisories)

With no unseen benchmark data left, a new test was built first: public PyPI
advisories published in 2026 (after the model's training data), each as a
pair — the code before the fix and after it
([`docs/cve_replay_protocol.md`](docs/cve_replay_protocol.md)). A system
succeeds on a pair when it flags the place the fix changed before the fix and
not after. v6 then adds ideas taken from other open-source agents, compared
one by one in [`docs/SOLISHTIRUV.md`](docs/SOLISHTIRUV.md): control strength
and a five-verdict verifier (OpenAnt), context by symbol name (Vulnhuntr),
attacker framing for authorization claims, retries, SARIF output.

| System | Detected | Pair success (95% CI) |
|---|---|---|
| Single-shot LLM | 1 of 30 | 0.00 (0.00–0.11) |
| Agent v5 | 5 of 30 | 0.10 (0.04–0.26) |
| **Agent v6** | 6 of 30 | 0.13 (0.05–0.30) |

Honest reading: **no measurable gain from v6 over v5** (4 pairs against 3,
identical intervals); both agents beat the single-shot baseline, which solved
none. The rule that looked best during development — telling strong controls
from weak ones in the scan — went from 2 to 5 pairs on the development half
and from 1 to 1 on the test half. And real library code is far harder than
teaching apps: 23 of 30 advisories were not found by any system. On the
earlier sets v6 is also noisier than v5 on authorization (FastAPI: 5 more
true findings, 70 more false ones). **v7** removes that regression — the
cause turned out to be the five-verdict format itself, under which the model
withdraws less — and adds Python 2 sources, per-project word lists
(`secagent.yml`) and `--changed-since <ref>` for reviewing a change. On Flask
and Django it has v5's false positives with one or two more true positives; on
a third half of 16 unseen advisories it solved 3 pairs against v5's 1, with
overlapping intervals and about 40% more findings to read. So v7 is the most
complete mode and v5 the quietest; neither is shown to be better at finding
vulnerabilities. Details: [`docs/experiments.md`](docs/experiments.md), T15
and T16.

## Quick start

Tested from a fresh clone on Windows 11 (Python 3.10, Ollama 0.35, RTX 3050 8 GB); 120 tests pass (no model needed).

```bash
python -m venv .venv && .venv/Scripts/pip install -r requirements.txt   # use .venv/bin/ on Linux/macOS
ollama pull qwen3:8b

# knowledge index — built offline from the committed corpus (data/knowledge/)
.venv/Scripts/python scripts/build_index.py
# (only to rebuild the corpus from the original sources, needs network:)
#   .venv/Scripts/python scripts/fetch_sources.py && .venv/Scripts/python scripts/build_knowledge.py

# review a codebase you are authorized to review
.venv/Scripts/python -m secagent review --target targets/demo_app            # v2 (default)
.venv/Scripts/python -m secagent review --target targets/demo_app --mode v3  # + authorization analysis
.venv/Scripts/python -m secagent review --target targets/demo_app --mode v1
#   -> runs/<timestamp>/report.md, final.json, trace.jsonl

# tests (no model needed)
.venv/Scripts/python -m pytest -q

# evaluation (needs Ollama; RealVuln targets are fetched, not committed)
.venv/Scripts/python -m secagent.evaluate --dataset holdout --systems semgrep single_shot agent_v2
.venv/Scripts/python scripts/fetch_realvuln.py
.venv/Scripts/python -m secagent.evaluate --dataset realvuln --systems agent_v2
.venv/Scripts/python scripts/fetch_realvuln.py --framework fastapi --out eval/realvuln_fastapi --commit 7a710251f55c17d32d3adcb13d37468e2e3b9e4a
.venv/Scripts/python -m secagent.evaluate --dataset realvuln_fastapi --systems agent_v3
.venv/Scripts/python scripts/fetch_realvuln.py --framework django --out eval/realvuln_django --commit 7a710251f55c17d32d3adcb13d37468e2e3b9e4a
.venv/Scripts/python -m secagent.evaluate --dataset realvuln_django --systems agent_v4
.venv/Scripts/python scripts/fetch_realvuln.py --framework other --out eval/realvuln_other --commit 7a710251f55c17d32d3adcb13d37468e2e3b9e4a
.venv/Scripts/python -m secagent.evaluate --dataset realvuln_other --systems agent_v5
.venv/Scripts/python scripts/build_cve_replay.py                             # 2026 advisories, vulnerable/fixed pairs
.venv/Scripts/python -m secagent.evaluate --dataset cve_test --systems agent_v6 && .venv/Scripts/python scripts/cve_pairs.py cve_test
.venv/Scripts/python scripts/injection_suite.py --harden                     # prompt-injection suite
```

Close GPU-heavy desktop apps first: with ~3 GB of VRAM taken by other programs
the model spills to CPU and becomes unusably slow (measured in T01).

## How it works

**v2 (default): controller-driven coverage sweep + verification**

```
every .py file (vendored/test dirs skipped)
   │  cut into windows of whole definitions (AST), ≤120 lines
   ▼
for each window ── read_file (logged event id) ─┐
   + routes of that file (AST: path, methods, decorators,
     auth-related names in the handler)          │
   + review questions from the knowledge cards   │
   ▼                                              │
model lists candidates {family, reason, line, title}   (schema-constrained)
   │  line must be inside the window that was read
   ▼
verifier (separate call, ±25 lines): analysis FIRST, then claim_holds;
   withdraw only with a control line it was shown
   ▼
finding = candidate + evidence {file, line, excerpt taken from the read, event id}
   ▼
report.md / final.json / trace.jsonl
```

**v3 (`--mode v3`): v2 + deterministic authorization seeds** — before the
sweep, `authz.py` builds an ownership map (models with an owner column or a FK
to a user table) and per-route facts (id parameters, auth level from
decorators / `Depends` / `before_request` / in-body checks, owner comparison
with the current user). Handlers that load an owned object by a request id
without an owner comparison, take the owner id from the request, or do
something sensitive without authentication while sibling routes authenticate,
become candidates. Each goes through the same verifier, with the route facts
and guarded sibling handlers as context. No model is needed for this step.

**v1 (`--mode v1`): tool-using agent loop** — one pass per family, the model
chooses `search_code` / `read_file` / `scan_static` / `retrieve_knowledge`
calls; the controller validates every typed decision, applies hypothesis
updates only with observed evidence, compacts context, and accepts a finding
only with evidence from code it read. Kept for comparison: on both datasets it
read too little code (recall 0.09–0.41).

Shared by both: read-only tools confined to the authorized root, no shell, no
network (localhost model only), repository content wrapped in nonce-delimited
untrusted blocks, Pydantic-validated outputs, append-only trace.

## Design decisions (short)

| Decision | Why |
|---|---|
| Hybrid: static signals + model reasoning, not model-only | LLM-only detectors are near chance on vulnerable/fixed pairs; SAST + LLM complement each other (research notes) |
| One pass per vulnerability family | a single open-ended pass stopped after its first finding; scoped prompts do better in published work |
| Evidence rules in the controller, not the prompt | the 8B model never used the hypothesis-update protocol; findings built from search hits named the wrong route |
| Separate refutation-oriented verifier | removed both look-alike false positives on the dev target; same-model bias acknowledged and measured by ablation |
| Retrieval kept, but not claimed to improve detection | pre-registered 2026 study: raw CVE/CWE retrieval did not improve Python detection; used for explanation/remediation, measured by ablation |
| 8K context, compaction, newest observation never hidden | 16K spills to CPU on this GPU (6 tok/s); Ollama silently truncates over-long prompts |
| No fine-tuning in the MVP | published wins need large curated/RL pipelines; naive SFT learns surface patterns |
| Read-only, localhost only, no code execution | prior project audit found LLM-written code executed on the host; agents reading untrusted input must not also have an outbound channel |

Longer: [`docs/research.md`](docs/research.md) (prior art, papers, datasets),
[`docs/knowledge_base.md`](docs/knowledge_base.md),
[`docs/experiments.md`](docs/experiments.md), [`docs/tasks.md`](docs/tasks.md).

## Safety boundaries

- Review only code you own or are authorized to review. The agent never
  executes the reviewed code, never contacts the network (endpoint must be
  localhost), and cannot write files outside its run directory.
- Paths are resolved and confined to the authorized root (symlinks, `..`,
  drive-relative paths and prefix confusion are rejected; see `tests/`).
- Lab verification is designed but off (Docker isolation not enabled on the
  development machine); every finding is reported as `verification_status:
  not_run`.

## Repository map

```
secagent/      agent: controller, tools, policy, schemas, verifier, review, report, evaluate
rules/         project-authored Semgrep taint rules + rule tests
data/          sources.jsonl, security_catalog.yaml, knowledge cards, built corpus
scripts/       knowledge ingestion, index build, Ollama benchmark, card validation
eval/holdout/  frozen synthetic evaluation apps + manifest (ground truth)
targets/       development/demo target (not evaluation data)
docs/          research, knowledge base, experiments, evaluation protocol, tasks
tests/         pytest suite (no model required)
```
