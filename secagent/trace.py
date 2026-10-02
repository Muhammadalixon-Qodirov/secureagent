"""Append-only run trace. Every tool call gets an event id that findings cite.

The JSONL file stores arguments, status, timing and content hashes, not raw file
contents (the reviewed code may contain secrets). Full results stay in memory for
the run so the report validator can check cited excerpts against what was read.
"""

from __future__ import annotations

import json
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


class Trace:
    def __init__(self, run_dir: Path | None = None):
        self.run_dir = run_dir
        self.path = None
        if run_dir is not None:
            run_dir.mkdir(parents=True, exist_ok=True)
            self.path = run_dir / "trace.jsonl"
        self._n = 0
        self.records: list[dict] = []

    def next_event_id(self) -> str:
        self._n += 1
        return f"E{self._n:04d}"

    def record(self, event: dict) -> None:
        event = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"), **event}
        self.records.append(event)
        if self.path is not None:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(event, ensure_ascii=False) + "\n")

    def reliability(self) -> dict:
        """Per-tool call counts by status and mean duration (idea taken from the XOUS tracing report)."""
        by_tool: dict[str, Counter] = defaultdict(Counter)
        dur: dict[str, list[float]] = defaultdict(list)
        for r in self.records:
            if "tool" not in r:
                continue
            by_tool[r["tool"]][r["status"]] += 1
            dur[r["tool"]].append(r.get("duration_ms", 0))
        return {t: {**dict(c), "mean_ms": round(sum(dur[t]) / len(dur[t]), 1)} for t, c in sorted(by_tool.items())}


class Timer:
    def __enter__(self):
        self.t0 = time.perf_counter()
        return self

    def __exit__(self, *exc):
        self.ms = round((time.perf_counter() - self.t0) * 1000, 1)
        return False
