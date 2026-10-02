"""Local model adapter (Ollama native /api/chat, schema-constrained output)."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Protocol

from .config import Config
from .schemas import DecisionAdapter


@dataclass
class ModelReply:
    content: str
    prompt_tokens: int | None = None
    output_tokens: int | None = None
    duration_ms: float = 0.0
    done_reason: str | None = None


class ModelError(Exception):
    pass


class ModelAdapter(Protocol):
    def decide(self, messages: list[dict], schema: dict | None = None) -> ModelReply: ...


class OllamaModel:
    """`format` carries the full Decision JSON schema; Ollama turns it into a grammar,
    so the reply is syntactically a decision. Pydantic still validates it."""

    def __init__(self, config: Config, num_predict: int = 2048, timeout_s: int = 600, seed: int = 0):
        self.config = config
        self.url = config.local_endpoint.rstrip("/") + "/api/chat"
        self.num_predict = num_predict
        self.timeout_s = timeout_s
        self.seed = seed
        self.schema = DecisionAdapter.json_schema()

    def decide(self, messages: list[dict], schema: dict | None = None) -> ModelReply:
        body = {
            "model": self.config.model, "messages": messages, "stream": False, "think": False,
            "format": schema or self.schema, "keep_alive": "10m",
            "options": {"num_ctx": self.config.max_context_tokens, "num_predict": self.num_predict,
                        "temperature": 0, "seed": self.seed},
        }
        req = urllib.request.Request(self.url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
        t0 = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                d = json.load(resp)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ModelError(f"model call failed: {exc}") from exc
        return ModelReply(content=d["message"]["content"], prompt_tokens=d.get("prompt_eval_count"),
                          output_tokens=d.get("eval_count"), done_reason=d.get("done_reason"),
                          duration_ms=round((time.perf_counter() - t0) * 1000, 1))
