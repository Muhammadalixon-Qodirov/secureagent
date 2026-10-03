# Engineering tasks

A task is done only when its acceptance criterion is shown with evidence.

| Task | Goal | Status | Evidence / check |
|---|---|---|---|
| K0 | Knowledge base: sources, catalog, cards, index | done | `python scripts/validate_cards.py` → 5 cards, 71 refs valid; `docs/knowledge_base.md` |
| R0 | Research before building | done | `docs/research.md` |
| T01 | Environment + baseline: real local model call, real scanner output, explicit blockers | done | `scripts/bench_ollama.py` → `runs/t01/`; `semgrep --test rules/ --metrics=off` 4/4; `docs/experiments.md#t01` |
| T02 | Schemas + policy: Config, Decision, Hypothesis, Finding; illegal action and root escape rejected | done | `pytest` → 33 passed (`tests/test_policy.py`, `tests/test_schemas.py`) |
| T03 | Tool adapters: bounded read/search, Semgrep JSON, tool event ids, line numbers + content hash | done | `pytest` → 50 passed (`tests/test_tools.py`); real-code smoke + 2 bug fixes in `docs/experiments.md#t03` |
| T04 | Knowledge retrieval as a tool (FTS5, CWE filter, provenance) | done | `retrieve_knowledge` returns source URL/version/license; `test_retrieve_knowledge_with_cwe_filter` |
| T05 | Agent loop: runtime prompt, one decision per turn, hypothesis state, budgets, loop detection | done | `pytest` → 78 passed; 6 real runs on `targets/demo_app`, fixes + regression tests in `docs/experiments.md#t05` |
| T06 | Reporting: JSON + Markdown, semantic validator (excerpts match read lines, ids resolve) | done | `secagent/report.py` (links/images/HTML neutralised, safe code fences); `tests/test_report.py`; example `runs/t05_demo_6/report.md` |
| T07 | Evaluation: synthetic holdout + RealVuln Flask subset, baselines + ablations | done | `eval/results/RESULTS.md`; `docs/experiments.md#t07`; protocol + 5 deviations |
| T08 | Optional lab verifier (Docker, no network) | blocked: Docker Desktop not running | — |
| T09 | Clean-setup reproduction, demo, submission notes | done | fresh clone: tests pass, offline index build, demo run; `docs/SUBMISSION.md` |
| T10 | v3: deterministic authorization analysis (ownership map, route auth facts, consistency) seeding IDOR candidates; learned FP filter | done | `secagent/authz.py`, `tests/test_authz.py`, `scripts/authz_dev_check.py`; filter: negative result (`eval/fp_filter/`); `docs/experiments.md#t10` |
| T11 | Independent test of v3 on RealVuln FastAPI, frozen before v3 existed, each system once | done | `docs/fastapi_protocol.md`, `eval/results_fastapi/RESULTS.md`, `docs/experiments.md#t11` |
| T12 | Prompt-injection suite (8 clean/injected pairs, 3 seeds) and controller hardening | done | `scripts/injection_suite.py`, `eval/injection/`, `secagent/hardening.py`, `docs/experiments.md#t12` |

## Open decisions (owner)

- MVP scope: Flask only (current default) vs. adding Django/FastAPI for more evaluation cases.
- Ollama server: enable flash attention + q8_0 KV cache (needs a server restart).
- Download `qwen2.5-coder:7b` (4.7 GB) as the comparison model.
