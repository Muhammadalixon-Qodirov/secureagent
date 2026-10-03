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
[`docs/experiments.md#t09`](docs/experiments.md). Two more experiments are in
T08: a learned false-positive filter (negative result, not adopted) and a
prompt-injection suite (`scripts/injection_suite.py`,
[`eval/injection/`](eval/injection/)).

## Quick start

Tested from a fresh clone on Windows 11 (Python 3.10, Ollama 0.35, RTX 3050 8 GB); 97 tests pass (no model needed).

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
