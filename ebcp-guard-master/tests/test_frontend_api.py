"""What the story page and dashboard depend on: reveal round trip, safe log feed, real reports."""

import httpx
import pytest
from tortoise import Tortoise

from app.main import app

TENANT = "bank_a"
EMAIL, PHONE, ACCOUNT = "rohan.gupta@example.in", "+919876543210", "123456789012"
REQUEST = {
    "endpoint": "/api/v1/payments",
    "destination_service": "internal_payment",
    "tenant_id": TENANT,
    "processing_purpose_hint": "PAYMENT_PROCESSING",
    "payload": {"email": EMAIL, "phone": PHONE, "account_number": ACCOUNT},
}


@pytest.fixture(autouse=True)
async def db():
    await Tortoise.init(db_url="sqlite://:memory:", modules={"models": ["app.database.models"]})
    await Tortoise.generate_schemas()
    yield
    await Tortoise.close_connections()


async def call(method, path, body=None, key=None):
    headers = {"X-API-Key": key} if key else {}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as client:
        return await client.request(method, f"/api/v1{path}", json=body, headers=headers)


async def encrypted_entities():
    res = await call("POST", "/protect", REQUEST)
    assert res.status_code == 200
    found = [e for e in res.json()["entity_decisions"] if e["action"] == "ENCRYPT"]
    assert found
    return found


def decrypt_body(entity):
    return {
        "cipher_id": entity["cipher_id"],
        "ciphertext_b64": entity["ciphertext_b64"],
        "entity_type": entity["entity_type"],
        "purpose": entity["purpose"],
        "tenant_id": TENANT,
    }


async def test_protected_values_can_be_revealed_by_an_authorized_service():
    originals = {"EMAIL": EMAIL, "PHONE": PHONE, "ACCOUNT_NUMBER": ACCOUNT}
    for entity in await encrypted_entities():
        res = await call("POST", "/decrypt", decrypt_body(entity), "test-payment-key")
        assert res.status_code == 200
        assert res.json()["decrypted_value"] == originals[entity["entity_type"]]


@pytest.mark.parametrize("key,expected", [(None, 401), ("test-reporting-key", 403)])
async def test_reveal_refuses_the_wrong_caller_without_leaking(key, expected):
    entity = (await encrypted_entities())[0]
    res = await call("POST", "/decrypt", decrypt_body(entity), key)
    assert res.status_code == expected
    assert EMAIL not in res.text and ACCOUNT not in res.text


async def test_wrong_purpose_cannot_decrypt():
    entity = (await encrypted_entities())[0]
    res = await call("POST", "/decrypt", decrypt_body(entity) | {"purpose": "ANALYTICS"}, "test-payment-key")
    assert res.status_code != 200
    assert "decrypted_value" not in res.text


async def test_feed_holds_no_original_values_and_records_denials():
    entity = (await encrypted_entities())[0]
    await call("POST", "/decrypt", decrypt_body(entity))  # refused: no key
    res = await call("GET", f"/audit/events?tenant_id={TENANT}")
    assert res.status_code == 200
    for value in (EMAIL, PHONE, ACCOUNT, entity["ciphertext_b64"]):
        assert value not in res.text
    events = res.json()
    assert {"PROTECTION_APPLIED", "DENIED_DECRYPTION"} <= {e["event_type"] for e in events}
    assert [e["sequence_number"] for e in events] == sorted((e["sequence_number"] for e in events), reverse=True)
    assert set(events[0]) == {
        "sequence_number", "event_type", "entity_types", "sensitivity_class",
        "protection_action", "risk_score", "created_at", "hash_prefix",
    }


async def test_feed_is_limited_to_the_callers_tenants_once_deployed(monkeypatch):
    from app.config import get_settings
    monkeypatch.setattr(get_settings(), "app_env", "production")
    assert (await call("GET", f"/audit/events?tenant_id={TENANT}")).status_code == 401
    assert (await call("GET", f"/audit/events?tenant_id={TENANT}", key="test-fraud-key")).status_code == 403
    assert (await call("GET", f"/audit/events?tenant_id={TENANT}", key="test-payment-key")).status_code == 200


async def test_evaluation_serves_the_real_reports():
    res = await call("GET", "/evaluation")
    assert res.status_code == 200
    report = res.json()["head_to_head"]
    assert report["test_records"] == 450
    assert set(report["systems"]) == {"EBCP-Guard (regex)", "Presidio (stock)", "Presidio + EBCP regexes"}
    assert report["systems"]["EBCP-Guard (regex)"]["scores"]["per_type"]["PERSON"]["f1"] == 0.0
