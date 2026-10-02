"""Trusted run configuration. Scope and limits come from here, never from the model."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

KNOWN_TOOLS = {"list_files", "read_file", "search_code", "scan_static", "retrieve_knowledge", "run_lab_check"}
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


class Config(BaseModel):
    model_config = ConfigDict(extra="forbid")

    model: str = "qwen3:8b"
    local_endpoint: str = "http://localhost:11434"
    authorized_roots: list[Path] = Field(min_length=1)
    enabled_tools: list[str] = ["list_files", "read_file", "search_code", "scan_static", "retrieve_knowledge"]
    enabled_families: list[str] = ["sql_injection", "path_traversal", "authorization_idor"]
    response_language: str = "en"
    max_model_calls: int = Field(default=40, ge=1)
    max_tool_calls: int = Field(default=60, ge=1)
    max_seconds: int = Field(default=1800, ge=1)
    max_file_bytes: int = Field(default=200_000, ge=1)
    max_context_tokens: int = Field(default=8192, ge=1024)   # T01: 8K is the GPU-resident ceiling
    runtime_tests_enabled: bool = False
    lab_manifest: Path | None = None

    @field_validator("local_endpoint")
    @classmethod
    def _local_only(cls, v: str) -> str:
        # The agent reads untrusted code; it must not have an outbound channel (Agents Rule of Two).
        host = urlparse(v).hostname
        if host not in LOCAL_HOSTS:
            raise ValueError(f"local_endpoint must be on localhost, got host {host!r}")
        return v

    @field_validator("enabled_tools")
    @classmethod
    def _known_tools(cls, v: list[str]) -> list[str]:
        unknown = set(v) - KNOWN_TOOLS
        if unknown:
            raise ValueError(f"unknown tools: {sorted(unknown)}")
        return v

    @field_validator("authorized_roots")
    @classmethod
    def _canonical_roots(cls, v: list[Path]) -> list[Path]:
        roots = []
        for r in v:
            rr = Path(r).expanduser().resolve()
            if not rr.is_dir():
                raise ValueError(f"authorized root is not a directory: {rr}")
            roots.append(rr)
        return roots

    @model_validator(mode="after")
    def _lab_requires_manifest(self):
        if "run_lab_check" in self.enabled_tools and not (self.runtime_tests_enabled and self.lab_manifest):
            raise ValueError("run_lab_check requires runtime_tests_enabled and a lab_manifest")
        if self.runtime_tests_enabled and self.lab_manifest is None:
            raise ValueError("runtime_tests_enabled requires a lab_manifest")
        return self


def load_config(path: str | Path) -> Config:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return Config.model_validate(data)
