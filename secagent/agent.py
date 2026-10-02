"""Controller loop: one model decision per turn, executed and checked by code.

The model only proposes. The controller
  - validates each reply against the contract (one bounded repair, then stop),
  - applies hypothesis updates only when their evidence was observed,
  - executes tools through the registry (policy, limits, event ids),
  - refuses repeated identical actions and enforces model/tool/time budgets,
  - keeps the prompt inside the context window (old observations -> one-line summaries),
  - accepts a final finding only if its evidence, excerpts and sources check out.
When it cannot get a valid final decision it builds a `partial` one from its own
state; it never reports findings the model did not support with evidence.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import ValidationError

from .config import Config
from .evidence import check_ref, excerpt_matches, observed_text
from .model import ModelAdapter, ModelError, ModelReply
from .prompt import Renderer, load_runtime_prompt, tool_signatures
from .schemas import (ActionDecision, Coverage, FinalDecision, Finding, HypothesisSummary, HypothesisUpdate,
                      parse_decision)
from .state import HypothesisStore
from .tools import ToolRegistry
from .verifier import verify_finding

# Initial chars-per-token guess; recalibrated from Ollama's real prompt token counts after
# every call. A fixed 3.0 over-estimated tokens ~1.7x and caused needless compaction (T05 run 1).
INITIAL_CHARS_PER_TOKEN = 3.5
CALIBRATION_SAFETY = 0.9
MAX_CONSECUTIVE_DUPLICATES = 3
MAX_INVALID_REPLIES = 3          # per run; invalid finals alternating with actions otherwise loop to the budget


@dataclass
class RunStats:
    model_calls: int = 0
    tool_calls: int = 0
    repairs: int = 0
    invalid_replies: int = 0
    duplicate_actions: int = 0
    rejected_updates: int = 0
    excerpt_corrections: int = 0
    rejected_findings: int = 0
    compactions: int = 0
    evidence_rebound: int = 0
    verifier_confirmed: int = 0
    verifier_refuted: int = 0
    verifier_uncertain: int = 0
    max_prompt_est_tokens: int = 0
    seconds: float = 0.0


@dataclass
class RunResult:
    final: FinalDecision
    stop_reason: str
    stats: RunStats
    controller_notes: list[str] = field(default_factory=list)


@dataclass
class _Turn:
    assistant: str
    observation: str
    summary: str


class Agent:
    def __init__(self, config: Config, model: ModelAdapter, registry: ToolRegistry,
                 num_predict: int = 2048, keep_full: int = 2, system_prompt: str | None = None,
                 verify: bool = True):
        self.config = config
        self.verify = verify
        self.model = model
        self.tools = registry
        self.trace = registry.trace
        self.num_predict = num_predict
        self.keep_full = keep_full
        self.system_prompt = system_prompt or load_runtime_prompt()
        self.renderer = Renderer()
        self.store = HypothesisStore()
        self.stats = RunStats()
        self.notes: list[str] = []
        self.chars_per_token = INITIAL_CHARS_PER_TOKEN

    # ------------------------------------------------------------------ context

    def _messages(self, turns: list[_Turn], context: str, pending: str, keep_full: int, terse: bool) -> list[dict]:
        msgs = [{"role": "system", "content": self.system_prompt}, {"role": "user", "content": context}]
        for i, t in enumerate(turns):
            full = i >= len(turns) - keep_full
            assistant = t.assistant
            if terse and not full:
                assistant = _terse_action(t.assistant)
            msgs.append({"role": "assistant", "content": assistant})
            msgs.append({"role": "user", "content": t.observation if full else t.summary})
        state = ("CONTROLLER STATE (trusted)\n" + self.store.render() + "\n" + self._budget_line()
                 + ("\n" + pending if pending else ""))
        msgs[-1] = {"role": "user", "content": msgs[-1]["content"] + "\n\n" + state}
        return msgs

    def _fit(self, turns: list[_Turn], context: str, pending: str) -> list[dict] | None:
        limit = self.config.max_context_tokens - self.num_predict - 256
        # The newest observation is never compacted: the model has not seen it yet (T05 run 1 bug).
        min_keep = 1 if turns else 0
        for terse in (False, True):
            for keep in range(min(self.keep_full, len(turns)), min_keep - 1, -1):
                msgs = self._messages(turns, context, pending, keep, terse)
                est = int(sum(len(m["content"]) for m in msgs) / self.chars_per_token)
                if est <= limit:
                    if keep < min(self.keep_full, len(turns)) or terse:
                        self.stats.compactions += 1
                    self.stats.max_prompt_est_tokens = max(self.stats.max_prompt_est_tokens, est)
                    return msgs
        return None

    def _budget_line(self) -> str:
        return (f"budget used: model_calls {self.stats.model_calls}/{self.config.max_model_calls}, "
                f"tool_calls {self.stats.tool_calls}/{self.config.max_tool_calls}")

    # ------------------------------------------------------------------ run

    def run(self, task: str, run_dir: Path | None = None) -> RunResult:
        t0 = time.monotonic()
        signatures = tool_signatures({n: m for n, (m, _) in self.tools._tools.items()
                                      if n in self.config.enabled_tools})
        context = self.renderer.run_context(self.config, task, signatures)
        turns: list[_Turn] = []
        pending = ""                      # controller notes for the next turn
        executed: dict[str, str] = {}     # action key -> event id
        consecutive_dupes = 0
        must_finalize = False
        stop_reason = "final"
        final: FinalDecision | None = None
        final_repairs_left = 1

        while True:
            elapsed = time.monotonic() - t0
            last_call = self.stats.model_calls >= self.config.max_model_calls - 1
            if not must_finalize and (last_call or self.stats.tool_calls >= self.config.max_tool_calls
                                      or elapsed > self.config.max_seconds):
                must_finalize = True
                pending += ("\nCONTROLLER: budget exhausted. Your next reply MUST be a FinalDecision "
                            "(status partial if the review is unfinished).")
            if self.stats.model_calls >= self.config.max_model_calls:
                stop_reason = "model budget exhausted"
                break

            msgs = self._fit(turns, context, pending)
            if msgs is None:
                stop_reason = "context window exhausted"
                break
            pending = ""

            try:
                reply = self._call(msgs, run_dir)
            except ModelError as exc:
                stop_reason = f"model unavailable: {exc}"
                break

            decision, error = self._parse(reply)
            if decision is None:
                self.stats.invalid_replies += 1
                if (self.stats.invalid_replies >= MAX_INVALID_REPLIES
                        or (turns and turns[-1].observation.startswith("CONTROLLER: invalid"))):
                    stop_reason = "repeated invalid model output"
                    break
                self.stats.repairs += 1
                turns.append(_Turn(reply.content[:600],
                                   f"CONTROLLER: invalid decision ({error}). Return one valid JSON decision.",
                                   "[compacted] previous reply was invalid"))
                continue

            if isinstance(decision, FinalDecision):
                problems = self._accept_final(decision)
                if problems and final_repairs_left > 0:
                    final_repairs_left -= 1
                    self.stats.repairs += 1
                    turns.append(_Turn(reply.content,
                                       "CONTROLLER: final decision rejected:\n- " + "\n- ".join(problems[:12])
                                       + "\nFix these and return a corrected FinalDecision.",
                                       "[compacted] final decision rejected once"))
                    continue
                final = self._drop_invalid_findings(decision, problems)
                if self.verify and final.findings:
                    final = self._verify(final)
                break

            if must_finalize:
                stop_reason = "budget exhausted; model did not finalize"
                break

            obs, summary, consecutive_dupes = self._act(decision, executed, consecutive_dupes)
            turns.append(_Turn(reply.content, obs, summary))
            if consecutive_dupes >= MAX_CONSECUTIVE_DUPLICATES:
                stop_reason = "repeated identical actions"
                break

        if final is None:
            final = self._fallback_final(stop_reason)
        self.stats.seconds = round(time.monotonic() - t0, 1)
        result = RunResult(final=final, stop_reason=stop_reason, stats=self.stats, controller_notes=self.notes)
        self.trace.record({"type": "run_end", "stop_reason": stop_reason, "status": final.status,
                           "findings": len(final.findings), "stats": self.stats.__dict__})
        if run_dir is not None:
            run_dir.mkdir(parents=True, exist_ok=True)
            (run_dir / "final.json").write_text(final.model_dump_json(indent=2, by_alias=True), encoding="utf-8")
        return result

    # ------------------------------------------------------------------ steps

    def _call(self, msgs: list[dict], run_dir: Path | None) -> ModelReply:
        self.stats.model_calls += 1
        reply = self.model.decide(msgs)
        chars = sum(len(m["content"]) for m in msgs)
        if reply.prompt_tokens and reply.prompt_tokens > 200:
            # prompt_tokens includes chat-template tokens, so this slightly under-estimates chars/token
            self.chars_per_token = CALIBRATION_SAFETY * chars / reply.prompt_tokens
        raw_hash = hashlib.sha256(reply.content.encode()).hexdigest()
        self.trace.record({"type": "model_turn", "turn": self.stats.model_calls,
                           "prompt_chars": chars, "chars_per_token_used": round(self.chars_per_token, 2),
                           "prompt_tokens": reply.prompt_tokens, "output_tokens": reply.output_tokens,
                           "done_reason": reply.done_reason, "duration_ms": reply.duration_ms,
                           "reply_sha256": raw_hash})
        if run_dir is not None:          # local only: replies can quote reviewed code
            run_dir.mkdir(parents=True, exist_ok=True)
            with (run_dir / "model_replies.jsonl").open("a", encoding="utf-8") as fh:
                fh.write(json.dumps({"turn": self.stats.model_calls, "content": reply.content}, ensure_ascii=False) + "\n")
        return reply

    @staticmethod
    def _parse(reply: ModelReply):
        try:
            return parse_decision(reply.content), None
        except ValidationError as exc:
            errs = "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors()[:6])
            if reply.done_reason == "length":
                errs = "reply was cut off at the output limit (shorten it); " + errs
            return None, errs

    def _act(self, d: ActionDecision, executed: dict[str, str], dupes: int) -> tuple[str, str, int]:
        notes = []
        if d.hypothesis_update is not None:
            rejected = self.store.apply(d.hypothesis_update, self.tools.results)
            if rejected:
                self.stats.rejected_updates += 1
                notes.append("CONTROLLER: hypothesis update rejected (state unchanged): " + "; ".join(rejected))

        key = json.dumps([d.tool, d.arguments], sort_keys=True, ensure_ascii=False)
        if key in executed and self.tools.results[executed[key]].status == "ok":
            self.stats.duplicate_actions += 1
            msg = (f"CONTROLLER: identical to {executed[key]}; not executed again. "
                   "Use that result, choose a different action, or return the final decision.")
            obs = "\n".join(notes + [msg])
            return obs, f"[compacted] duplicate of {executed[key]}", dupes + 1

        self.stats.tool_calls += 1
        result = self.tools.execute(d.tool, d.arguments)
        executed.setdefault(key, result.event_id)
        obs = "\n".join(notes + [self.renderer.observation(result)])
        return obs, self.renderer.summary(result, d.arguments), 0

    # ------------------------------------------------------------------ final checks

    def _accept_final(self, final: FinalDecision) -> list[str]:
        problems: list[str] = []
        for upd in final.hypothesis_updates:
            rejected = self.store.apply(upd, self.tools.results)
            if rejected:
                self.stats.rejected_updates += 1
                problems += rejected
        retrieved = {x["id"] for r in self.tools.results.values()
                     if r.tool == "retrieve_knowledge" and r.status == "ok" for x in r.data["results"]}
        for f in final.findings:
            self._rebind_to_reads(f)
            # Evidence must include code the model actually read: search/scanner hits are hypotheses.
            # (T05 run 3: an IDOR finding built only from search hits named the wrong route.)
            read_backed = any(ev.tool_event_id in self.tools.results
                              and self.tools.results[ev.tool_event_id].tool == "read_file"
                              and not check_ref(ev, self.tools.results) for ev in f.evidence)
            if not read_backed:
                ev0 = f.evidence[0]
                problems.append(f"{f.id}: evidence comes only from search/scanner hits. Read the code with "
                                f"read_file around {ev0.file}:{ev0.line_start} (handler, callers, decorators) and "
                                "cite the lines you read. Do not drop a finding just to pass this check; "
                                "drop it only if the code you read shows it is not a vulnerability.")
            for ev in list(f.evidence) + list(f.counterevidence):
                reason = check_ref(ev, self.tools.results)
                if reason:
                    problems.append(f"{f.id}: evidence {ev.file}:{ev.line_start}-{ev.line_end}: {reason}")
                    continue
                if excerpt_matches(ev, self.tools.results) is False:
                    text = observed_text(ev, self.tools.results)
                    ev.excerpt = text[:500]
                    self.stats.excerpt_corrections += 1
                    self.notes.append(f"{f.id}: excerpt for {ev.file}:{ev.line_start}-{ev.line_end} replaced "
                                      f"with the lines observed in {ev.tool_event_id}")
            # A citation that was not retrieved is removed, not fatal: the finding stands on its
            # code evidence. (T05 run 2: a correct SQLi finding was dropped because the model put
            # the reviewed file into `sources`.)
            unbacked = [s.id for s in f.sources if s.id not in retrieved]
            if unbacked:
                f.sources = [s for s in f.sources if s.id in retrieved]
                self.notes.append(f"{f.id}: removed sources not retrieved in this run: {', '.join(unbacked)}")
            if f.verification_status != "not_run" and not self.config.runtime_tests_enabled:
                problems.append(f"{f.id}: verification_status {f.verification_status} but lab checks are disabled")
            if f.verification_status == "not_run" and (f.verification.event_ids or f.verification.observations):
                self.notes.append(f"{f.id}: verification event_ids/observations cleared - no lab check ran "
                                  f"(was: {f.verification.event_ids} / {[o[:80] for o in f.verification.observations]})")
                f.verification = f.verification.model_copy(update={"event_ids": [], "observations": []})
            # A finding that names a hypothesis the model never recorded: create it from the finding
            # itself (claim + its own evidence, still checked) instead of rejecting a supported finding.
            # (T05 run 3: the model "fixed" this rejection by deleting a correct path traversal finding.)
            for hid in f.hypothesis_ids:
                if hid not in self.store.items:
                    refs = [{k: getattr(ev, k) for k in ("file", "line_start", "line_end", "tool_event_id")}
                            for ev in f.evidence if not check_ref(ev, self.tools.results)]
                    created = self.store.apply(HypothesisUpdate(
                        id=hid, claim=f.title, entrypoint=f.entrypoint, family=f.cwe_id,
                        sink_or_protected_operation=f.source_to_sink, supporting_evidence=refs,
                        analysis_status="candidate"), self.tools.results)
                    if not created:
                        self.notes.append(f"{f.id}: hypothesis {hid} was not recorded by the model; "
                                          "created by the controller from the finding")
        return problems

    def _rebind_to_reads(self, f: Finding) -> None:
        """If evidence cites a search/scanner hit for lines the model later read with read_file,
        cite the read instead. (T05 run 4: the model read lines 22-26 as asked but kept citing the
        earlier search event.)"""
        reads = [r for r in self.tools.results.values() if r.tool == "read_file" and r.status == "ok"]
        for ev in f.evidence:
            src = self.tools.results.get(ev.tool_event_id)
            if src is None or src.tool not in ("search_code", "scan_static"):
                continue
            for r in reversed(reads):
                d = r.data
                if d["path"] == ev.file and d["start_line"] <= ev.line_start and ev.line_end <= d["end_line"]:
                    self.notes.append(f"{f.id}: evidence {ev.file}:{ev.line_start}-{ev.line_end} rebound from "
                                      f"{ev.tool_event_id} ({src.tool}) to {r.event_id} (read_file)")
                    ev.tool_event_id = r.event_id
                    self.stats.evidence_rebound += 1
                    break

    def _verify(self, final: FinalDecision) -> FinalDecision:
        kept, limitations, summaries = [], list(final.limitations), list(final.coverage.hypotheses)
        for f in final.findings:
            v, window_event = verify_finding(f, self.model, self.tools, self.renderer)
            self.trace.record({"type": "verifier", "finding": f.id, "verdict": v.verdict,
                               "control_lines": v.control_lines, "window_event": window_event})
            tag = f"independent verifier ({window_event}): {v.verdict} - {v.reason[:300]}"
            if v.verdict == "refuted":
                self.stats.verifier_refuted += 1
                limitations.append(f"{f.id} withdrawn: verifier refuted it; control at lines "
                                   f"{v.control_lines} ({window_event}): {v.reason[:300]}")
                summaries = [s for s in summaries if s.finding_id != f.id]
                for hid in f.hypothesis_ids:
                    summaries.append(HypothesisSummary(
                        id=hid, question=f.title, analysis_status="rejected", verification_status="not_run",
                        reason=f"refuted by verifier: {v.reason[:200]}", finding_id=None))
                continue
            if v.verdict == "uncertain":
                self.stats.verifier_uncertain += 1
                f = f.model_copy(update={"confidence": "low",
                                         "confidence_rationale": f.confidence_rationale + " | " + tag})
            else:
                self.stats.verifier_confirmed += 1
                f = f.model_copy(update={"confidence_rationale": f.confidence_rationale + " | " + tag})
            kept.append(f)
        coverage = final.coverage.model_copy(update={"hypotheses": summaries})
        return final.model_copy(update={"findings": kept, "limitations": limitations, "coverage": coverage})

    def _drop_invalid_findings(self, final: FinalDecision, problems: list[str]) -> FinalDecision:
        if not problems:
            return final
        bad = {p.split(":", 1)[0] for p in problems}
        kept = [f for f in final.findings if f.id not in bad]
        dropped = [f.id for f in final.findings if f.id in bad]
        self.stats.rejected_findings += len(dropped)
        limitations = list(final.limitations) + [f"controller rejected: {p}" for p in problems]
        status = "partial" if (dropped or final.status == "complete") and problems else final.status
        return final.model_copy(update={"findings": kept, "limitations": limitations, "status": status})

    def _fallback_final(self, reason: str) -> FinalDecision:
        reviewed = sorted({r.data["path"] for r in self.tools.results.values()
                           if r.tool == "read_file" and r.status == "ok"})
        hyps = [HypothesisSummary(id=h.id, question=h.claim or h.id, analysis_status=h.analysis_status,
                                  verification_status="not_run",
                                  reason="controller fallback; no validated final decision", finding_id=None)
                for h in self.store.items.values()]
        status = "blocked" if not self.tools.results else "partial"
        return FinalDecision(
            kind="final", status=status, findings=[],
            coverage=Coverage(reviewed_paths=reviewed,
                              reviewed_entrypoints=sorted({h.entrypoint for h in self.store.items.values() if h.entrypoint}),
                              checks=sorted({r.tool for r in self.tools.results.values()}),
                              hypotheses=hyps, omitted_areas=[]),
            limitations=[f"run stopped: {reason}",
                         "no findings reported: the model did not return a validated final decision",
                         *self.notes],
            hypothesis_updates=[])


def _terse_action(raw: str) -> str:
    try:
        d = json.loads(raw)
        if d.get("kind") == "action":
            return json.dumps({"kind": "action", "tool": d.get("tool"), "arguments": d.get("arguments"),
                               "hypothesis_id": d.get("hypothesis_id")}, ensure_ascii=False)
    except (json.JSONDecodeError, AttributeError):
        pass
    return raw[:300]
