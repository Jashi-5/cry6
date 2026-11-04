"""Streaming attack endpoint: real step order, incremental delivery, unchanged outcomes."""

import asyncio
import json
import threading

import httpx
import pytest

from app.api.routes import simulate
from app.api.schemas.schemas import AttackSimulationRequest, AttackSimulationResponse
from app.main import app
import simulations.attack_scenarios as scenarios

STAGES = ["attack_initiated", "target_analysis", "attack_execution", "security_verification", "final_result"]
VECTORS = ["plaintext_log", "dict_attack", "cross_tenant", "cumulative", "unauth_decrypt", "audit_tamper", "exfiltration", "evasion"]


def request(scenario):
    return AttackSimulationRequest(scenario=scenario, tenant_id="demo_bank")


@pytest.mark.parametrize("scenario", VECTORS)
async def test_stream_reports_every_stage_and_same_outcome_as_plain_endpoint(scenario):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post("/api/v1/simulate-attack/stream", json={"scenario": scenario})
        plain = (await client.post("/api/v1/simulate-attack", json={"scenario": scenario})).json()

    assert res.status_code == 200
    events = [json.loads(line) for line in res.text.splitlines()]
    assert [e["stage"] for e in events] == STAGES
    result = events[-1]["result"]
    assert result["scenario"] == scenario
    assert result["result"] == plain["result"]
    assert result["explanation"] == plain["explanation"]


async def test_events_are_delivered_while_the_scenario_is_still_running(monkeypatch):
    release = threading.Event()

    def blocked_handler(req, progress):
        progress("target_analysis", "first step")
        assert release.wait(5), "scenario was not released: stream is buffering"
        return AttackSimulationResponse(
            scenario=req.scenario, baseline_outcome="b", ebcp_guard_outcome="e",
            result="PROTECTED", details={}, explanation="x",
        )

    monkeypatch.setattr(scenarios, "attack_1_plaintext_log", blocked_handler)
    stream = simulate.attack_event_stream(request("plaintext_log"))

    first = json.loads(await asyncio.wait_for(anext(stream), 2))
    second = json.loads(await asyncio.wait_for(anext(stream), 2))
    assert (first["stage"], second["stage"]) == ("attack_initiated", "target_analysis")

    release.set()  # only now can the scenario finish
    assert json.loads(await asyncio.wait_for(anext(stream), 2))["stage"] == "final_result"


async def test_scenario_crash_sends_generic_error_without_internal_detail(monkeypatch):
    def broken_handler(req, progress):
        raise RuntimeError("secret-key-material")

    monkeypatch.setattr(scenarios, "attack_1_plaintext_log", broken_handler)
    lines = [line async for line in simulate.attack_event_stream(request("plaintext_log"))]

    assert json.loads(lines[-1])["stage"] == "error"
    assert "secret-key-material" not in "".join(lines)
