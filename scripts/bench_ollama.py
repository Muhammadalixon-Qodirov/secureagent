"""T01: measure the local model on this machine before building on it.

For each context size: does the prompt get truncated, how is the model split
between GPU and CPU, how fast are prompt processing and generation. Then: does
schema-constrained output (Ollama `format`) give valid, Pydantic-checked JSON.

    .venv/Scripts/python scripts/bench_ollama.py [--model qwen3:8b] [--ctx 4096 8192 16384]

Writes runs/t01/ollama_<model>.json. Uses only the native /api/chat endpoint
(the OpenAI-compatible /v1 endpoint ignores num_ctx).
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ValidationError

ROOT = Path(__file__).resolve().parent.parent
URL = "http://localhost:11434/api/chat"
TIMEOUT = 900
# measured on qwen3:8b: 438 filler lines -> 3866 prompt tokens (~8.8 tokens/line)
TOKENS_PER_LINE = 8.8


def chat(body: dict) -> dict:
    req = urllib.request.Request(URL, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return json.load(resp)


def ollama_ps(model: str) -> dict:
    out = subprocess.run(["ollama", "ps"], capture_output=True, text=True).stdout
    for line in out.splitlines()[1:]:
        if line.startswith(model):
            m = re.search(r"(\d+(?:\.\d+)?\s*[GM]B)\s+(.+?)\s{2,}(\d+)\s", line)
            if m:
                return {"size": m.group(1), "processor": m.group(2).strip(), "context": int(m.group(3))}
            return {"raw": line}
    return {}


def gpu_memory() -> dict:
    out = subprocess.run(["nvidia-smi", "--query-gpu=memory.used,memory.free", "--format=csv,noheader,nounits"],
                         capture_output=True, text=True).stdout.strip()
    used, free = (int(x) for x in out.split(","))
    return {"used_mib": used, "free_mib": free}


def unload(model: str) -> None:
    try:
        chat({"model": model, "messages": [], "keep_alive": 0})
    except Exception:
        pass


def filler(n_lines: int) -> str:
    return " ".join(f"line{i} the quick brown fox." for i in range(n_lines))


def context_run(model: str, num_ctx: int | None, n_lines: int) -> dict:
    prompt = "MARKER_START " + filler(n_lines) + " What was the very first word of this message? Answer with one word."
    options = {"temperature": 0, "seed": 7}
    if num_ctx:
        options["num_ctx"] = num_ctx
    t0 = time.time()
    try:
        d = chat({"model": model, "messages": [{"role": "user", "content": prompt}], "stream": False,
                  "think": False, "keep_alive": "2m", "options": options})
    except Exception as exc:
        return {"num_ctx": num_ctx, "error": f"{type(exc).__name__}: {exc}", "wall_s": round(time.time() - t0, 1),
                "ollama_ps": ollama_ps(model)}
    expected = int(n_lines * TOKENS_PER_LINE)
    return {
        "num_ctx": num_ctx,
        "expected_prompt_tokens": expected,
        "prompt_eval_count": d.get("prompt_eval_count"),
        # Ollama drops overflow silently (keeps ~half the window); detect it from the token count
        "truncated": d.get("prompt_eval_count", 0) < 0.9 * expected,
        "prompt_tok_per_s": round(d["prompt_eval_count"] / (d["prompt_eval_duration"] / 1e9), 1),
        "gen_tok_per_s": round(d["eval_count"] / (d["eval_duration"] / 1e9), 1),
        "load_s": round(d.get("load_duration", 0) / 1e9, 1),
        "wall_s": round(time.time() - t0, 1),
        "ollama_ps": ollama_ps(model),
        "gpu": gpu_memory(),
    }


class ReadFileArgs(BaseModel):
    path: str
    start_line: int
    end_line: int


class Decision(BaseModel):
    kind: Literal["action"]
    tool: Literal["read_file", "search_code"]
    arguments: ReadFileArgs
    purpose: str


STRUCTURED_PROMPT = (
    "You review a Flask app for SQL injection. Semgrep reported a possible issue at app/routes.py line 42. "
    "Decide the next tool call. Respond as JSON matching this schema: "
    + json.dumps(Decision.model_json_schema())
)


def structured_runs(model: str, num_ctx: int, n: int) -> dict:
    ok, errors = 0, []
    for i in range(n):
        try:
            d = chat({"model": model, "messages": [{"role": "user", "content": STRUCTURED_PROMPT}], "stream": False,
                      "think": False, "format": Decision.model_json_schema(), "keep_alive": "2m",
                      "options": {"temperature": 0, "seed": i, "num_ctx": num_ctx}})
            Decision.model_validate_json(d["message"]["content"])
            ok += 1
        except ValidationError as exc:
            errors.append(f"validation: {exc.errors()[0]['msg']}")
        except Exception as exc:
            errors.append(f"{type(exc).__name__}: {exc}")
    return {"runs": n, "valid": ok, "errors": errors[:5]}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="qwen3:8b")
    ap.add_argument("--ctx", type=int, nargs="+", default=[4096, 8192, 16384])
    ap.add_argument("--structured-runs", type=int, default=10)
    a = ap.parse_args()

    unload(a.model)
    result = {"model": a.model, "date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "ollama": subprocess.run(["ollama", "--version"], capture_output=True, text=True).stdout.strip(),
              "gpu_before": gpu_memory(), "context_runs": []}

    # default options (no num_ctx) with an oversized prompt, then ~75% of each window
    runs = [(None, 1200)] + [(c, int(c * 0.75 / TOKENS_PER_LINE)) for c in a.ctx]
    for num_ctx, n_lines in runs:
        unload(a.model)
        r = context_run(a.model, num_ctx, n_lines)
        result["context_runs"].append(r)
        print(json.dumps(r, ensure_ascii=False), flush=True)

    unload(a.model)
    result["structured"] = structured_runs(a.model, min(a.ctx), a.structured_runs)
    print("structured:", result["structured"], flush=True)

    out = ROOT / "runs" / "t01" / f"ollama_{a.model.replace(':', '_')}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"-> {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
