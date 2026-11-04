"""/protect and /analyze need a key except in development; audit and model status always do."""

import httpx
import pytest
from tortoise import Tortoise

from app.config import get_settings
from app.main import app
from app.nlp.model_loader import get_model_registry

GATEWAY = ["/protect", "/analyze"]
BODY = {"payload": {"phone": "9876501234"}, "tenant_id": "bank_a", "destination_service": "internal_payment"}


@pytest.fixture(autouse=True)
async def db():
    await Tortoise.init(db_url="sqlite://:memory:", modules={"models": ["app.database.models"]})
    await Tortoise.generate_schemas()
    await get_model_registry().load_all_models()
    yield
    await Tortoise.close_connections()


@pytest.fixture
def production(monkeypatch):
    monkeypatch.setattr(get_settings(), "app_env", "production")


async def post(path, body, key=None):
    headers = {"X-API-Key": key} if key else {}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as client:
        return await client.post(f"/api/v1{path}", json=body, headers=headers)


@pytest.mark.parametrize("path", GATEWAY)
async def test_development_stays_open_for_the_demo_page(path):
    assert (await post(path, BODY)).status_code == 200


@pytest.mark.parametrize("path", GATEWAY)
@pytest.mark.parametrize("key,expected", [
    (None, 401),
    ("wrong-key", 401),
    ("test-fraud-key", 403),  # valid key, tenant not covered
    ("test-payment-key", 200),
])
async def test_deployed_gateway_requires_a_key_for_the_tenant(production, path, key, expected):
    assert (await post(path, BODY, key)).status_code == expected


@pytest.mark.parametrize("key,expected", [(None, 401), ("test-fraud-key", 403), ("test-payment-key", 200)])
async def test_verify_audit_always_requires_a_key(key, expected):
    assert (await post("/verify-audit", {"tenant_id": "bank_a"}, key)).status_code == expected


async def test_model_status_always_requires_a_key():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as client:
        assert (await client.get("/api/v1/models/status")).status_code == 401
        assert (await client.get("/api/v1/models/status", headers={"X-API-Key": "test-payment-key"})).status_code == 200


async def test_health_stays_open_for_the_demo_page(production):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as client:
        assert (await client.get("/api/v1/health")).status_code == 200
