"""
EBCP-Guard FastAPI Route Integration Tests
============================================
Tests:
  - GET /api/v1/health
  - POST /api/v1/analyze
  - POST /api/v1/protect
  - POST /api/v1/tokenize
  - POST /api/v1/decrypt
  - POST /api/v1/simulate-attack
"""

import pytest
import httpx
from tortoise import Tortoise
from app.main import app
from app.nlp.model_loader import get_model_registry

@pytest.fixture(autouse=True)
async def init_test_db():
    await Tortoise.init(
        db_url="sqlite://:memory:",
        modules={"models": ["app.database.models"]},
    )
    await Tortoise.generate_schemas()
    # Ensure models are loaded
    registry = get_model_registry()
    await registry.load_all_models()
    yield
    await Tortoise.close_connections()

@pytest.mark.asyncio
async def test_health_endpoint():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "version" in data

@pytest.mark.asyncio
async def test_tokenize_endpoint():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        req_body = {
            "values": [{"entity_type": "EMAIL", "value": "test.user@bank.com"}],
            "tenant_id": "bank_test",
            "purpose": "ANALYTICS"
        }
        response = await client.post("/api/v1/tokenize", json=req_body, headers={"X-API-Key": "test-payment-key"})
        assert response.status_code == 200
        data = response.json()
        assert "tokens" in data
        assert len(data["tokens"]) == 1
        assert "token" in data["tokens"][0]

@pytest.mark.asyncio
async def test_simulate_attack_endpoint():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        req_body = {
            "scenario": "dict_attack",
            "tenant_id": "demo_bank"
        }
        response = await client.post("/api/v1/simulate-attack", json=req_body)
        assert response.status_code == 200
        data = response.json()
        assert data["result"] == "PROTECTED"
        assert "baseline_outcome" in data
        assert "ebcp_guard_outcome" in data

@pytest.mark.asyncio
async def test_analyze_endpoint():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        req_body = {
            "payload": {
                "customer_name": "Rohan Gupta",
                "email": "rohan.gupta@example.in",
                "account_number": "123456789012"
            },
            "endpoint": "/api/v1/payments",
            "http_method": "POST",
            "destination_service": "internal_payment",
            "tenant_id": "bank_test"
        }
        response = await client.post("/api/v1/analyze", json=req_body)
        assert response.status_code == 200
        data = response.json()
        assert "detected_entities" in data
        assert "sensitivity_class" in data
        assert "exposure_score" in data
        assert "recommended_action" in data

@pytest.mark.asyncio
async def test_protect_endpoint():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        req_body = {
            "payload": {
                "name": "Priya Sharma",
                "email": "priya.sharma@example.com",
                "pan": "ABCPS1234F"
            },
            "endpoint": "/api/v1/customer/profile",
            "destination_service": "marketing_crm",
            "tenant_id": "bank_test"
        }
        response = await client.post("/api/v1/protect", json=req_body)
        assert response.status_code == 200
        data = response.json()
        assert "protected_payload" in data
        assert "audit_event_id" in data
        assert len(data["audit_event_hash"]) == 64
        assert "entity_decisions" in data
        # Email and PAN should NOT be in the protected payload in plaintext
        protected = str(data["protected_payload"])
        assert "priya.sharma@example.com" not in protected
        assert "ABCPS1234F" not in protected


@pytest.mark.asyncio
@pytest.mark.parametrize("request_fields", [
    {"destination_service": "untrusted_external"},
    {"destination_service": "external_unknown"},
    {},
    {"destination_service": "internal_payment", "force_action": "BLOCK"},
    {"destination_service": "internal_payment", "force_action": "QUARANTINE"},
])
async def test_withheld_response_contains_no_plaintext(request_fields):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/protect", json={
            "payload": {
                "customer_name": "Ananya Iyer",
                "email": "ananya.iyer@example.com",
                "pan": "ABCPA5678K",
            },
            "endpoint": "/api/v1/analytics/events",
            "tenant_id": "bank_test",
            **request_fields,
        })
    assert response.status_code == 200
    data = response.json()
    assert data["protection_decision"] in ("BLOCK", "QUARANTINE")
    assert data["protected_payload"] == {}
    assert data["entity_decisions"] == []
    for secret in ("Ananya Iyer", "ananya.iyer@example.com", "ABCPA5678K"):
        assert secret not in response.text
