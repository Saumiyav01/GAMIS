"""Ollama and deterministic mock providers with bounded, schema-validated JSON responses."""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, TypeVar

from pydantic import BaseModel, ValidationError

T = TypeVar("T", bound=BaseModel)


class LLMError(RuntimeError):
    pass


class OllamaConnectionError(LLMError):
    pass


class OllamaModelUnavailableError(LLMError):
    pass


class LLMProvider(Protocol):
    def generate_json(self, prompt: str, response_model: type[T], *, model: str | None = None) -> T: ...
    def list_models(self) -> tuple[str, ...]: ...
    def model_available(self, model: str) -> bool: ...


@dataclass(frozen=True)
class LLMConfiguration:
    provider: str = "ollama"
    endpoint: str = "http://localhost:11434"
    supervisor_model: str = "qwen2.5:7b"
    worker_model: str = "qwen2.5:7b"
    research_model: str | None = None
    analysis_model: str | None = None
    verification_model: str | None = None
    timeout_seconds: float = 90.0
    retries: int = 1
    temperature: float = 0.2
    context_tokens: int = 8192

    @classmethod
    def from_environment(cls) -> "LLMConfiguration":
        _load_backend_env()
        return cls(provider=os.getenv("GAMIS_LLM_PROVIDER", "ollama").lower(),
                   endpoint=os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/"),
                   supervisor_model=os.getenv("GAMIS_SUPERVISOR_MODEL", "qwen2.5:7b"),
                   worker_model=os.getenv("GAMIS_WORKER_MODEL", "qwen2.5:7b"),
                   research_model=os.getenv("GAMIS_RESEARCH_MODEL") or None,
                   analysis_model=os.getenv("GAMIS_ANALYSIS_MODEL") or None,
                   verification_model=os.getenv("GAMIS_VERIFICATION_MODEL") or None,
                   timeout_seconds=float(os.getenv("GAMIS_LLM_TIMEOUT", "90")),
                   retries=int(os.getenv("GAMIS_LLM_RETRIES", "1")),
                   temperature=float(os.getenv("GAMIS_LLM_TEMPERATURE", "0.2")),
                   context_tokens=int(os.getenv("GAMIS_LLM_CONTEXT_TOKENS", "8192")))

    def model_for_role(self, role: str) -> str:
        role_models = {"evidence-reader": self.research_model, "intel-analyst": self.analysis_model,
                       "responder": self.verification_model}
        if role not in role_models:
            raise ValueError(f"unknown worker role {role!r}")
        return role_models[role] or self.worker_model


def _load_backend_env(env_file: Path | None = None) -> None:
    """Load backend/.env like dotenv without overriding the caller's environment."""
    env_file = env_file or Path(__file__).resolve().parents[2] / ".env"
    try:
        lines = env_file.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        name, separator, value = line.partition("=")
        name, value = name.strip(), value.strip()
        if not separator or not name or not name.replace("_", "").isalnum():
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        os.environ.setdefault(name, value)


class OllamaProvider:
    def __init__(self, endpoint: str = "http://localhost:11434", *, timeout_seconds: float = 90,
                 retries: int = 1, temperature: float = 0.2, context_tokens: int = 8192):
        if (timeout_seconds <= 0 or retries < 0 or retries > 5 or context_tokens < 512
                or not 0 <= temperature <= 2):
            raise ValueError("invalid Ollama timeout, retry count, temperature, or context limit")
        if not endpoint.startswith(("http://", "https://")):
            raise ValueError("Ollama endpoint must use HTTP or HTTPS")
        self.endpoint, self.timeout_seconds = endpoint.rstrip("/"), timeout_seconds
        self.retries, self.temperature, self.context_tokens = retries, temperature, context_tokens

    def list_models(self) -> tuple[str, ...]:
        data = self._request("/api/tags", {})
        models = data.get("models")
        if not isinstance(models, list):
            raise LLMError("Ollama returned an invalid model list")
        names = tuple(sorted(x["name"] for x in models if isinstance(x, dict) and isinstance(x.get("name"), str)))
        return names

    def model_available(self, model: str) -> bool:
        if not model:
            raise ValueError("model name is required")
        return model in self.list_models()

    def require_model(self, model: str) -> None:
        try:
            available = self.model_available(model)
        except LLMError as exc:
            raise OllamaConnectionError(
                f"Cannot connect to Ollama at {self.endpoint}. Start Ollama (or run `ollama serve`) "
                f"and retry. Details: {exc}") from exc
        if not available:
            raise OllamaModelUnavailableError(
                f"Ollama model {model!r} is not installed at {self.endpoint}; run `ollama pull {model}` "
                "or configure GAMIS_SUPERVISOR_MODEL / GAMIS_WORKER_MODEL.")

    def generate_json(self, prompt: str, response_model: type[T], *, model: str | None = None) -> T:
        if not model:
            raise ValueError("an Ollama model must be selected")
        if not prompt.strip():
            raise ValueError("prompt cannot be empty")
        if len(prompt) > self.context_tokens * 4:
            raise LLMError(f"prompt exceeds the configured context limit ({self.context_tokens} tokens)")
        payload = {"model": model, "stream": False, "format": response_model.model_json_schema(),
                   "messages": [{"role": "user", "content": prompt}],
                   "options": {"num_ctx": self.context_tokens, "temperature": self.temperature}}
        data = self._request("/api/chat", payload)
        try:
            content = data["message"]["content"]
            if not isinstance(content, str):
                raise TypeError("response content is not text")
            return response_model.model_validate_json(content)
        except (KeyError, TypeError, ValidationError, json.JSONDecodeError) as exc:
            raise LLMError(f"Ollama returned output that does not match {response_model.__name__}: {exc}") from exc

    def _request(self, path: str, payload: dict) -> dict:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(self.endpoint + path, data=body if payload else None,
                                         headers={"Content-Type": "application/json"}, method="POST" if payload else "GET")
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                    raw = response.read(8_000_001)
                    if len(raw) > 8_000_000:
                        raise LLMError("Ollama response exceeds the 8 MB response limit")
            except (urllib.error.URLError, TimeoutError) as exc:
                last_error = exc
                if attempt < self.retries:
                    time.sleep(min(0.25 * (2**attempt), 1.0))
                continue
            try:
                result = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise LLMError(f"Ollama returned an invalid JSON response from {path}: {exc}") from exc
            if not isinstance(result, dict):
                raise LLMError("Ollama returned a non-object response")
            return result
        raise OllamaConnectionError(
            f"Ollama request failed at {self.endpoint}{path}: {last_error}. "
            "Start Ollama (or run `ollama serve`) and retry.") from last_error


class MockProvider:
    """Deterministic local provider; no network, external API, or model is used."""

    def list_models(self) -> tuple[str, ...]:
        return ("gamis-deterministic-mock",)

    def model_available(self, model: str) -> bool:
        return model in self.list_models()

    def generate_json(self, prompt: str, response_model: type[T], *, model: str | None = None) -> T:
        if model not in (None, "gamis-deterministic-mock"):
            raise LLMError(f"mock provider does not implement model {model!r}")
        model_name = response_model.__name__
        if model_name == "MissionPlan":
            raw = {"tasks": [
                {"task_id": "research", "worker_role": "evidence-reader",
                 "objective": "Collect relevant synthetic network and authentication event evidence.",
                 "success_criteria": ["Cite gateway receipts and source event identifiers."], "depends_on": []},
                {"task_id": "analysis", "worker_role": "intel-analyst",
                 "objective": "Analyze the collected records for patterns and alternative explanations.",
                 "success_criteria": ["Distinguish observations from interpretation."], "depends_on": ["research"]},
                {"task_id": "verification", "worker_role": "responder",
                 "objective": "Verify claims against source records and identify evidence gaps.",
                 "success_criteria": ["Check claims against source evidence."], "depends_on": ["analysis"]}]}
        elif model_name == "LLMWorkerOutput":
            evidence_ids = _prompt_evidence_ids(prompt)
            if not evidence_ids:
                raise LLMError("mock worker requires at least one gateway-collected evidence item")
            if "role: responder" in prompt.lower():
                text = "Available synthetic records support a possible security incident, but do not establish attribution or impact."
            elif "role: intel-analyst" in prompt.lower():
                text = "Repeated failed logins followed by a successful login from the same source are suspicious."
            else:
                text = "Synthetic logs contain repeated failed login events and a subsequent successful login."
            raw = {"summary": text, "claims": [{
                "statement": text, "confidence": 0.75, "supporting_evidence_ids": [evidence_ids[0]],
                "contradicting_evidence_ids": [], "rationale": "Deterministic mock assessment of synthetic evidence."
            }], "limitations": ["Only synthetic log and intelligence sources are available."],
                   "missing_information": ["Production telemetry and impact evidence are unavailable."]}
        elif model_name == "LLMFinalAssessment":
            evidence_ids = _prompt_evidence_ids(prompt)
            if not evidence_ids:
                raise LLMError("mock final assessment requires gateway-collected evidence")
            text = ("The synthetic evidence indicates suspicious authentication activity, but is insufficient "
                    "to confirm real-world impact or attribution.")
            raw = {"executive_summary": text, "conclusion": text, "claims": [{
                "statement": "Synthetic records show potentially suspicious authentication activity.",
                "confidence": 0.7, "supporting_evidence_ids": evidence_ids[:3],
                "contradicting_evidence_ids": [], "rationale": "Based only on cited synthetic records."
            }], "missing_information": ["Real environment telemetry", "Confirmed impact and attribution"],
                   "limitations": ["Mock provider; no model inference was performed."], "confidence": 0.7}
        else:
            raise LLMError(f"mock provider does not implement structured response {model_name}")
        try:
            return response_model.model_validate(raw)
        except ValidationError as exc:
            raise LLMError(f"mock provider fixture does not match {model_name}: {exc}") from exc


def _prompt_evidence_ids(prompt: str) -> list[str]:
    marker = "Available evidence IDs: "
    try:
        return json.loads(prompt.split(marker, 1)[1].splitlines()[0])
    except (IndexError, json.JSONDecodeError) as exc:
        raise LLMError("prompt did not provide a valid available-evidence list") from exc


def create_provider(configuration: LLMConfiguration | None = None) -> LLMProvider:
    configuration = configuration or LLMConfiguration.from_environment()
    if configuration.provider == "mock":
        return MockProvider()
    if configuration.provider == "ollama":
        return OllamaProvider(configuration.endpoint, timeout_seconds=configuration.timeout_seconds,
                              retries=configuration.retries, temperature=configuration.temperature,
                              context_tokens=configuration.context_tokens)
    raise LLMError(f"unsupported LLM provider {configuration.provider!r}; use 'mock' or 'ollama'")
