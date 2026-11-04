"""Fix 1: detected values must never survive in a /protect payload."""

import json
import uuid

import httpx
import pytest
from tortoise import Tortoise

from app.detection.regex_detector import get_regex_detector
from app.main import app
from app.nlp.model_loader import get_model_registry
from app.services.protection_service import _replace_in_payload

PHONE = "9876501234"
ACCOUNT = "123456789012"


@pytest.fixture(autouse=True)
async def db():
    await Tortoise.init(db_url="sqlite://:memory:", modules={"models": ["app.database.models"]})
    await Tortoise.generate_schemas()
    await get_model_registry().load_all_models()
    yield
    await Tortoise.close_connections()


async def protect(payload):
    body = {"payload": payload, "destination_service": "third_party_analytics", "synthetic_customer_id": uuid.uuid4().hex}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as client:
        return (await client.post("/api/v1/protect", json=body)).json()


@pytest.mark.parametrize("payload,secret", [
    ({"phone": PHONE}, PHONE),
    ({"note": f"call {PHONE} today"}, PHONE),
    ({"account_number": int(ACCOUNT)}, ACCOUNT),
    ({"items": [int(ACCOUNT)]}, ACCOUNT),
    ({"rows": [[ACCOUNT, "other"]]}, ACCOUNT),
    ({"rows": [[{"deep": ACCOUNT}]]}, ACCOUNT),
    ({"lookup": {ACCOUNT: "active"}}, ACCOUNT),
])
async def test_value_never_survives_any_payload_shape(payload, secret):
    assert secret not in json.dumps((await protect(payload))["protected_payload"])


def test_sentence_keeps_its_spacing():
    payload = {"note": f"call {PHONE} today"}
    value = get_regex_detector().detect(payload["note"])[0].value
    assert value == PHONE


def test_unrelated_values_keep_their_types():
    payload = {"count": 3, "ok": True, "none": None, "ratio": 1.5, "secret": ACCOUNT}
    _replace_in_payload(payload, ACCOUNT, "TOKEN")
    assert payload == {"count": 3, "ok": True, "none": None, "ratio": 1.5, "secret": "TOKEN"}


async def test_output_is_withheld_if_replacement_misses_a_value(monkeypatch):
    # Simulates a future replacement bug: the safety net must block, not leak.
    monkeypatch.setattr("app.services.protection_service._replace_in_payload", lambda *a: None)
    out = await protect({"phone": PHONE})
    assert out["protection_decision"] == "BLOCK"
    assert out["protected_payload"] == {}
