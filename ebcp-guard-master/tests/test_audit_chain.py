"""Fix 3: the audit chain resists rewrites and deletions, and survives restarts."""

import asyncio
import uuid

import httpx
import pytest
from tortoise import Tortoise

from app.cryptography.audit_integrity import GENESIS_HASH, compute_event_hash
from app.database.models import AuditEvent
from app.main import app
from app.services.audit_service import record_audit_event

TENANT = "audit_test"


@pytest.fixture(autouse=True)
async def db():
    await Tortoise.init(db_url="sqlite://:memory:", modules={"models": ["app.database.models"]})
    await Tortoise.generate_schemas()
    yield
    await Tortoise.close_connections()


async def add(n=1):
    for _ in range(n):
        await record_audit_event(uuid.uuid4().hex, TENANT, None, "TEST", [], "S1", "MASK", 0.1)


async def verify():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as client:
        return (await client.post("/api/v1/verify-audit", json={"tenant_id": TENANT}, headers={"X-API-Key": "test-reporting-key"})).json()


async def ordered():
    return await AuditEvent.filter(tenant_id=TENANT).order_by("sequence_number")


async def test_clean_chain_verifies():
    await add(5)
    result = await verify()
    assert result["verified"] and result["checked_events"] == 5


async def test_rewrite_without_key_is_detected():
    await add(5)
    prev = GENESIS_HASH
    for i, event in enumerate(await ordered()):
        if i == 2:
            event.safe_metadata = {**event.safe_metadata, "protection_action": "ALLOW"}
        event.previous_hash = prev
        event.current_hash = prev = compute_event_hash(prev, event.safe_metadata)  # no key
        await event.save()
    assert not (await verify())["verified"]


async def test_deleted_newest_events_are_detected():
    await add(5)
    for event in (await ordered())[-2:]:
        await event.delete()
    result = await verify()
    assert not result["verified"]
    assert result["first_failed_sequence"] == 5


async def test_new_events_cannot_hide_a_deletion():
    await add(5)
    for event in (await ordered())[-2:]:
        await event.delete()
    await add(6)  # passes the old head; the checkpoint must stay frozen
    assert not (await verify())["verified"]


async def test_chain_continues_from_database_not_memory(monkeypatch):
    # A restart loses all process memory; only the database and checkpoint remain.
    await add(3)
    first = await ordered()
    await add(2)
    events = await ordered()
    assert [e.sequence_number for e in events] == [1, 2, 3, 4, 5]
    assert events[3].previous_hash == first[-1].current_hash
    assert (await verify())["verified"]


async def test_concurrent_events_do_not_fork_the_chain():
    await asyncio.gather(*(add() for _ in range(20)))
    events = await ordered()
    assert [e.sequence_number for e in events] == list(range(1, 21))
    assert (await verify())["verified"]


async def test_denied_decrypt_is_recorded():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as client:
        res = await client.post("/api/v1/decrypt", json={"cipher_id": "c", "ciphertext_b64": "AAAA", "tenant_id": TENANT})
    assert res.status_code == 401
    events = await ordered()
    assert [e.event_type for e in events] == ["DENIED_DECRYPTION"]
    assert (await verify())["verified"]
