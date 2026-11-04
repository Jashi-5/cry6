"""Fix 2: sensitive endpoints identify callers by API key, never by a name they send."""

import httpx
import pytest
from tortoise import Tortoise

from app.cryptography.encryption import encrypt_value
from app.main import app

SECRET = "123456789012"


@pytest.fixture(autouse=True)
async def db():
    await Tortoise.init(db_url="sqlite://:memory:", modules={"models": ["app.database.models"]})
    await Tortoise.generate_schemas()
    yield
    await Tortoise.close_connections()


async def post(path, body, key=None):
    headers = {"X-API-Key": key} if key else {}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as client:
        return await client.post(f"/api/v1{path}", json=body, headers=headers)


def decrypt_body(tenant="bank_a", **extra):
    package = encrypt_value(SECRET, "ACCOUNT_NUMBER", "bank_a", "PAYMENT_PROCESSING").cipher_package_b64
    return {"cipher_id": "c1", "ciphertext_b64": package, "tenant_id": tenant, **extra}


TOKENIZE = {"values": [{"entity_type": "EMAIL", "value": "a@example.com"}], "tenant_id": "bank_a", "purpose": "ANALYTICS"}


@pytest.mark.parametrize("key,expected", [
    (None, 401),
    ("wrong-key", 401),
    ("test-fraud-key", 403),      # valid key, tenant not covered
    ("test-payment-key", 200),
    ("test-reporting-key", 200),  # "*" covers every tenant
])
async def test_tokenize_access(key, expected):
    assert (await post("/tokenize", TOKENIZE, key)).status_code == expected


@pytest.mark.parametrize("key,body,expected", [
    (None, {}, 401),
    (None, {"requesting_service": "payment_service"}, 401),  # the original bypass
    ("wrong-key", {"requesting_service": "payment_service"}, 401),
    ("test-reporting-key", {}, 403),                         # no decrypt rights
    ("test-reporting-key", {"requesting_service": "payment_service"}, 403),
    ("test-fraud-key", {}, 403),                             # tenant not covered
])
async def test_decrypt_refused_without_leaking_plaintext(key, body, expected):
    res = await post("/decrypt", decrypt_body(**body), key)
    assert res.status_code == expected
    assert SECRET not in res.text


async def test_decrypt_with_correct_key_needs_no_service_name():
    res = await post("/decrypt", decrypt_body(), "test-payment-key")
    assert res.status_code == 200
    assert res.json()["decrypted_value"] == SECRET


async def test_exposure_requires_key():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as client:
        assert (await client.get("/api/v1/exposure/CUST1")).status_code == 401
        assert (await client.get("/api/v1/exposure/CUST1", headers={"X-API-Key": "test-payment-key"})).status_code == 200


async def test_no_configured_keys_refuses_everyone(monkeypatch):
    from app.config import get_settings
    monkeypatch.setattr(get_settings(), "service_api_keys", {})
    assert (await post("/tokenize", TOKENIZE, "test-payment-key")).status_code == 401
