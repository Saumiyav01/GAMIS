from __future__ import annotations

import time
from dataclasses import asdict

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from gamis.llm.provider import LLMConfiguration, MockProvider
from gamis.runtime import DEFAULT_OBJECTIVE, LocalRuntime


@pytest.fixture
def api_client(tmp_path, monkeypatch):
    monkeypatch.setenv("GAMIS_ENV", "test")
    runtime = LocalRuntime(tmp_path / "gamis", configuration=LLMConfiguration(provider="mock"),
                           provider=MockProvider())
    with TestClient(create_app(runtime=runtime)) as client:
        yield client, runtime


def _wait_for_terminal(client: TestClient, mission_id: str) -> dict:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        response = client.get(f"/api/missions/{mission_id}")
        assert response.status_code == 200, response.text
        mission = response.json()
        if mission["status"] not in {"RUNNING", "QUEUED"}:
            report = client.get(f"/api/missions/{mission_id}/report")
            if report.status_code == 200:
                return mission
        time.sleep(0.05)
    raise AssertionError(f"mission {mission_id} did not finish before timeout")


def test_mock_mission_api_integration_and_dashboard_contract(api_client):
    client, _runtime = api_client
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"

    models = client.get("/api/models?provider=mock")
    assert models.status_code == 200
    assert models.json()["available_models"] == ["gamis-deterministic-mock"]
    scenarios = client.get("/api/evaluation/scenarios")
    assert scenarios.status_code == 200
    assert scenarios.json()["scenarios"]

    submitted = client.post("/api/missions", json={"objective": DEFAULT_OBJECTIVE, "provider": "mock"})
    assert submitted.status_code == 202, submitted.text
    mission_id = submitted.json()["mission_id"]
    mission = _wait_for_terminal(client, mission_id)
    assert mission["status"] == "COMPLETE"
    assert mission["completed_tasks"] == mission["task_count"] == 3
    assert mission["receipt_count"] > 0
    assert mission["evidence_count"] > 0

    tasks = client.get(f"/api/missions/{mission_id}/tasks").json()["tasks"]
    assert len(tasks) == 3
    assert all(task["assignment"] and task["report"] for task in tasks)
    agents = client.get("/api/agents").json()["agents"]
    assert len(agents) == 3
    assert {agent["worker_id"] for agent in agents} == {
        task["assignment"]["worker_id"] for task in tasks
    }

    report = client.get(f"/api/missions/{mission_id}/report")
    assert report.status_code == 200
    assert report.json()["report"]["evidence_intelligence"] is not None
    evidence = client.get(f"/api/missions/{mission_id}/evidence")
    assert evidence.status_code == 200
    assert evidence.json()["evidence"]
    assert all(row["integrity"]["status"] == "VERIFIED" for row in evidence.json()["evidence"])
    receipts = client.get(f"/api/missions/{mission_id}/receipts").json()["receipts"]
    assert len(receipts) == mission["receipt_count"]
    gateway = client.get(f"/api/missions/{mission_id}/gateway").json()
    assert gateway["decisions"] and gateway["receipts"]
    assert gateway["uncertain_actions"] == []

    ledger = client.get("/api/ledger?limit=1000")
    assert ledger.status_code == 200
    assert ledger.json()["events"]
    verification = client.get("/api/ledger/verify").json()
    assert verification["chain_status"] == "VERIFIED"

    dashboard = client.get("/")
    assert dashboard.status_code == 200
    assert "no demo data" in dashboard.text.lower()
    assert "/api/missions" in dashboard.text
    assert "/api/models?provider=" in dashboard.text
    assert "const DEMO" not in dashboard.text
    assert "simulate(" not in dashboard.text


def test_browser_cannot_change_authority_or_execute_gateway_requests(api_client):
    client, _runtime = api_client
    invalid = client.post("/api/missions", json={
        "objective": DEFAULT_OBJECTIVE, "provider": "mock", "host": "attacker-controlled",
        "budget": 999999,
    })
    assert invalid.status_code == 422
    assert invalid.json()["error"]["code"] == "INVALID_REQUEST"
    assert client.get("/api/missions").json()["missions"] == []

    gateway = client.post("/api/gateway/requests", json={
        "worker_id": "worker-reader-1", "tool_id": "case_action", "operation_id": "execute",
    })
    assert gateway.status_code == 501
    assert gateway.json()["error"]["code"] == "DIRECT_GATEWAY_REQUEST_UNAVAILABLE"
    approvals = client.get("/api/approvals")
    assert approvals.status_code == 501
    assert approvals.json()["error"]["code"] == "APPROVALS_UNAVAILABLE"
    decision = client.post("/api/approvals/APR-1/decision", json={"decision": "approved"})
    assert decision.status_code == 501


def test_mission_cancellation_uses_runtime_and_blocks_resume(api_client):
    client, runtime = api_client
    grant = runtime.create_grant(DEFAULT_OBJECTIVE, "web-01", "203.0.113.50")
    runtime.mission_store.create(grant, DEFAULT_OBJECTIVE, runtime.clock())
    runtime.mission_store.save_execution_config(grant.mission_id, asdict(runtime.configuration))

    cancelled = client.post(f"/api/missions/{grant.mission_id}/cancel")
    assert cancelled.status_code == 200, cancelled.text
    recovery = client.get(f"/api/missions/{grant.mission_id}/recovery").json()
    assert recovery["cancel_requested"] is True
    assert recovery["grant_state"] == "SUSPENDED"
    assert recovery["resume_eligible"] is False
    resume = client.post(f"/api/missions/{grant.mission_id}/resume")
    assert resume.status_code == 409


def test_ollama_unavailable_is_reported_without_creating_a_mission(tmp_path, monkeypatch):
    monkeypatch.setenv("GAMIS_ENV", "test")
    configuration = LLMConfiguration(provider="ollama", endpoint="http://127.0.0.1:1",
                                      timeout_seconds=0.1)
    runtime = LocalRuntime(tmp_path / "gamis", configuration=configuration)
    with TestClient(create_app(runtime=runtime)) as client:
        response = client.post("/api/missions", json={
            "objective": DEFAULT_OBJECTIVE, "provider": "ollama",
            "supervisor_model": "local-model", "research_model": "local-model",
            "analysis_model": "local-model", "verification_model": "local-model",
        })
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "PROVIDER_UNAVAILABLE"
        assert client.get("/api/missions").json()["missions"] == []


def test_cors_is_limited_to_local_development_origins(api_client):
    client, _runtime = api_client
    local = client.options("/api/missions", headers={
        "Origin": "http://localhost:5173", "Access-Control-Request-Method": "POST",
    })
    assert local.status_code == 200
    assert local.headers["access-control-allow-origin"] == "http://localhost:5173"

    remote = client.options("/api/missions", headers={
        "Origin": "https://example.invalid", "Access-Control-Request-Method": "POST",
    })
    assert "access-control-allow-origin" not in remote.headers
