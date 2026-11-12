from __future__ import annotations

import json
import urllib.error

import pytest

from gamis.agents.models import LLMGeneratedClaim, LLMWorkerOutput
from gamis.llm.provider import (LLMConfiguration, LLMError, OllamaConnectionError,
                                OllamaModelUnavailableError, OllamaProvider, _load_backend_env)


class _Response:
    def __init__(self, value: dict):
        self.payload = json.dumps(value).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self, _limit: int) -> bytes:
        return self.payload


class _RawResponse(_Response):
    def __init__(self, value: bytes):
        self.payload = value


def test_ollama_connection_failure_has_startup_guidance_and_bounded_retries(monkeypatch):
    attempts = []

    def fail(_request, *, timeout):
        attempts.append(timeout)
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", fail)
    provider = OllamaProvider(retries=1)
    with pytest.raises(OllamaConnectionError, match="ollama serve"):
        provider.list_models()
    assert len(attempts) == 2


def test_ollama_model_unavailable_has_pull_command(monkeypatch):
    monkeypatch.setattr("urllib.request.urlopen",
                        lambda _request, *, timeout: _Response({"models": [{"name": "other:latest"}]}))
    with pytest.raises(OllamaModelUnavailableError, match="ollama pull qwen2.5:7b"):
        OllamaProvider(retries=0).require_model("qwen2.5:7b")


def test_ollama_structured_output_uses_temperature_and_context(monkeypatch):
    output = {"summary": "A test summary.", "claims": [{
        "statement": "A cited record exists.", "confidence": 0.8,
        "supporting_evidence_ids": ["EV-1"], "contradicting_evidence_ids": [],
        "rationale": "The input identifies the record."
    }], "limitations": [], "missing_information": []}
    request_payloads = []

    def respond(request, *, timeout):
        request_payloads.append(json.loads(request.data))
        return _Response({"message": {"content": json.dumps(output)}})

    monkeypatch.setattr("urllib.request.urlopen", respond)
    provider = OllamaProvider(retries=0, temperature=0.65, context_tokens=4096)
    result = provider.generate_json("Analyze evidence.", LLMWorkerOutput, model="qwen2.5:7b")
    assert result.claims[0].supporting_evidence_ids == ("EV-1",)
    assert request_payloads[0]["options"] == {"num_ctx": 4096, "temperature": 0.65}
    assert request_payloads[0]["format"]["title"] == "LLMWorkerOutput"


def test_ollama_invalid_structured_response_fails_explicitly(monkeypatch):
    monkeypatch.setattr("urllib.request.urlopen",
                        lambda _request, *, timeout: _Response({"message": {"content": "{not-json"}}))
    with pytest.raises(LLMError, match="does not match LLMWorkerOutput"):
        OllamaProvider(retries=0).generate_json("Analyze evidence.", LLMWorkerOutput, model="qwen2.5:7b")


def test_ollama_invalid_api_json_is_not_misreported_as_connection_failure(monkeypatch):
    monkeypatch.setattr("urllib.request.urlopen", lambda _request, *, timeout: _RawResponse(b"{invalid"))
    with pytest.raises(LLMError, match="invalid JSON response"):
        OllamaProvider(retries=0).list_models()


def test_generated_claim_schema_requires_evidence_references():
    schema = LLMGeneratedClaim.model_json_schema()
    assert {"supporting_evidence_ids", "contradicting_evidence_ids"} <= set(schema["required"])
    with pytest.raises(ValueError, match="must cite"):
        LLMGeneratedClaim.model_validate({
            "statement": "Unsupported claim.", "confidence": 0.2,
            "supporting_evidence_ids": [], "contradicting_evidence_ids": [],
            "rationale": "No cited evidence.",
        })


def test_configuration_reads_dotenv_and_respects_environment_override(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "GAMIS_LLM_PROVIDER=ollama\nOLLAMA_HOST=http://127.0.0.1:11435\n"
        "GAMIS_SUPERVISOR_MODEL=supervisor:latest\nGAMIS_WORKER_MODEL=worker:latest\n"
        "GAMIS_RESEARCH_MODEL=research:latest\nGAMIS_ANALYSIS_MODEL=analysis:latest\n"
        "GAMIS_VERIFICATION_MODEL=verification:latest\n"
        "GAMIS_LLM_TIMEOUT=12\nGAMIS_LLM_RETRIES=2\nGAMIS_LLM_TEMPERATURE=0.4\n"
        "GAMIS_LLM_CONTEXT_TOKENS=2048\n", encoding="utf-8")
    names = ("GAMIS_LLM_PROVIDER", "OLLAMA_HOST", "GAMIS_SUPERVISOR_MODEL", "GAMIS_WORKER_MODEL",
             "GAMIS_RESEARCH_MODEL", "GAMIS_ANALYSIS_MODEL", "GAMIS_VERIFICATION_MODEL",
             "GAMIS_LLM_TIMEOUT", "GAMIS_LLM_RETRIES", "GAMIS_LLM_TEMPERATURE", "GAMIS_LLM_CONTEXT_TOKENS")
    for name in names:
        monkeypatch.delenv(name, raising=False)
    _load_backend_env(env_file)
    monkeypatch.setenv("GAMIS_WORKER_MODEL", "override:latest")
    config = LLMConfiguration.from_environment()
    assert config.provider == "ollama"
    assert config.endpoint == "http://127.0.0.1:11435"
    assert config.supervisor_model == "supervisor:latest"
    assert config.worker_model == "override:latest"
    assert config.model_for_role("evidence-reader") == "research:latest"
    assert config.model_for_role("intel-analyst") == "analysis:latest"
    assert config.model_for_role("responder") == "verification:latest"
    assert (config.timeout_seconds, config.retries, config.temperature, config.context_tokens) == (12, 2, 0.4, 2048)
