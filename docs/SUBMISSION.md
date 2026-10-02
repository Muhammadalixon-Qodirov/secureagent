# Reply to Safia (draft)

> Fill in: `[UNIVERSITY]`. Review the "How I worked" paragraph and keep
> it accurate to how you used AI assistance.

---

**Subject:** Re: ML Engineer case study — local AI security agent

Dear Fahriddin,

Thank you for the case study. My submission is here: **https://github.com/Muhammadalixon-Qodirov/secureagent**

I am a 4th-year full-time student in the Artificial Intelligence program at
[UNIVERSITY].

**What I built.** `secagent`, a security review agent for Python/Flask code that
runs fully on my laptop (qwen3:8b via Ollama on an 8 GB RTX 3050; nothing leaves
the machine). It looks for SQL injection, path traversal and broken
object-level authorization (IDOR) and reports only findings tied to lines it
has actually read, with an audit trail of every tool call.

**Key decisions** (details in the README and `docs/`):

- **Controller in code, not in the prompt.** Tools are read-only and confined
  to the authorized folder; no shell, no network; repository text is wrapped as
  untrusted data. A finding is accepted only with evidence the controller can
  check against what was read. A prior project of mine executed LLM-written
  code on the host — I designed this one so that cannot happen.
- **Measure before claiming.** I froze two evaluations before running them
  (a 48-case synthetic holdout and 15 public Flask apps from the RealVuln
  benchmark, 130 labelled entries), compared against Semgrep and a
  single-prompt LLM baseline, and logged every deviation.
- **Knowledge used where it helps.** I built a 49-source knowledge base
  (CWE, OWASP, framework docs) with provenance. Recent studies show raw CWE
  retrieval does not improve Python detection, so I measured it: the model
  never used retrieval, but structured review questions from my knowledge
  cards did improve results (F1 0.38 → 0.53).

**The failed experiment.** My first, pre-declared agent (a tool-using loop
with a self-verifier) failed on the holdout: recall 0.09. The verifier, which
had looked good on my development app, withdrew most true positives — often
while describing the vulnerability in its own reasoning — and the loop
searched instead of reading code (45 searches, 1 read in the authorization
passes). From that I built v2: the controller shows the model every window of
code, with an AST route map, and a redesigned verifier reasons before it
decides. Judged once on RealVuln under a frozen protocol:

| | Precision | Recall | F1 | False positives |
|---|---|---|---|---|
| Semgrep | 0.90 | 0.10 | 0.18 | 1 |
| Single-prompt LLM | 0.48 | 0.36 | 0.41 | 35 |
| Agent v1 | 0.73 | 0.09 | 0.16 | 3 |
| **Agent v2** | **0.75** | 0.33 | **0.46** | 10 |

**Honest limits.** IDOR (11/53) and path traversal (2/9) are still weak; the
RealVuln apps are public, so the model may have seen them; samples are small;
greedy decoding was not fully deterministic; lab-based exploit verification is
designed but not enabled.

**How I worked.** I wrote the specification and runtime prompt
(`AI_SECURITY_AGENT_PROMPT.md`, `SECURITY_AGENT_SYSTEM_PROMPT.md`) and built
the system with an AI coding assistant; the research notes, experiment log and
protocols in `docs/` record the decisions and why they were made.

To try it: `README.md` → Quick start (about 10 minutes; tested from a fresh
clone; 93 tests run without a model).

Best regards,
Muhammadalixon Qodirov
