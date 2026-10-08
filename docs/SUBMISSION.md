# Reply to Safia

The email sent with the submission. The full history of each round, with all
tables, is in [`experiments.md`](experiments.md) and the [README](../README.md).

---

**Subject:** Re: ML Engineer case study — local AI security agent

Dear Fahriddin,

Thank you for the case study. My submission:
https://github.com/Muhammadalixon-Qodirov/secureagent

I am a 4th-year full-time student in the Artificial Intelligence program at
Tashkent State University of Economics (TSUE).

**What I built.** secagent, a security code-review agent for Python web apps
that runs entirely on my laptop (qwen3:8b via Ollama, 8 GB GPU; nothing leaves
the machine). It looks for SQL injection, path traversal and broken
object-level authorization, never executes the reviewed code, and reports only
findings tied to lines it has actually read.

**How I measured it.** Before each version I froze a test set that version had
never seen, stated what I expected, and ran every system once:

| Test set (unseen) | Agent | Agent result | Single-prompt LLM |
|---|---|---|---|
| 15 Flask apps | v2 | F1 0.46 | F1 0.41 |
| 21 FastAPI apps | v3 | F1 0.24 | F1 0.14 |
| 23 Django apps | v4 | F1 0.10 | F1 0.18 |
| 5 apps, other frameworks | v5 | F1 0.46 | F1 0.21 |
| 30 real 2026 advisories* | v5 / v6 | 3 / 4 solved | 0 solved |
| 16 more real 2026 advisories* | v5 / v7 | 1 / 3 solved | not run |

\* the code before and after the fix; a system must flag the first and not the
second.

**What I learned.**

- My first agent failed its own pre-declared test (recall 0.09): the verifier
  withdrew true findings and the loop searched instead of reading. That led to
  a controller in code that decides what the model reads.
- Numbers from the set I developed on never transferred: v3 scored 0.51 on
  Flask, where it was developed, and 0.24 on FastAPI; v4 then scored 0.10 on
  Django, where the agent lost to a single prompt. I found the cause (the
  model read the right files and listed nothing), and the next version, which
  finds risky operations in code and gives the model one claim at a time, did
  what I predicted on unseen apps.
- I then compared my agent with 17 open-source projects and added their
  ideas. On real 2026 advisories this gave no measurable gain, and one
  borrowed idea made things worse: offered five verdicts instead of yes/no,
  the model withdraws fewer wrong claims. I measured that, fixed it, and
  report it as it is.
- I attacked my own agent with prompt injection: 3 of 8 attacks hid a real SQL
  injection. After fixes in the controller, none do.

**Honest limits.** Authorization findings on unfamiliar code are mostly false
alarms (precision around 0.1–0.2), and on real library code they are almost
never found (1 of 20 advisories). On real advisories the agents solved at most
about one in five (3 of 16; 4 of 30). The test sets are small and the
intervals overlap. The agent only reads code; it does not confirm findings by
exploitation.

**How I worked.** I set the direction and made the decisions; most of the
code, experiments and documentation were written and run by an AI coding
assistant (Claude Code) under my direction. The experiment log and protocols
in `docs/` record each decision, including the ones that did not work.

**To try it:** README → Quick start (about 10 minutes; 120 tests run without a
model). Full results: `docs/experiments.md`.

**A request about feedback.** Whatever you decide, I would be grateful for
your feedback. If the decision is not to move forward, I would appreciate it
if you could explain the reasons in as much detail as you are able to share,
and tell me what I would have needed to do differently to be hired. I am at
the stage of building experience: I am learning how the application process
works and what is expected of an ML engineer in practice, and I want to study
my mistakes and close the gaps in my knowledge.

Best regards,
Muhammadalixon Qodirov
