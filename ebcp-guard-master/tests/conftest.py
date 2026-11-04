"""Test configuration. Set before the app is imported, so real .env values are not used."""
import hashlib
import json
import os
import tempfile
from pathlib import Path

import pytest

TEST_KEYS = {"payment_service": "test-payment-key", "fraud_service": "test-fraud-key", "reporting_service": "test-reporting-key"}
TENANTS = {"payment_service": ["bank_test", "bank_a"], "fraud_service": ["bank_b"], "reporting_service": ["*"]}
CHECKPOINT = Path(tempfile.gettempdir()) / f"ebcp_test_checkpoint_{os.getpid()}.json"

os.environ["APP_ENV"] = "development"
os.environ["SERVICE_API_KEYS"] = json.dumps({
    name: {"key_sha256": hashlib.sha256(key.encode()).hexdigest(), "tenants": TENANTS[name]}
    for name, key in TEST_KEYS.items()
})
os.environ["AUDIT_CHECKPOINT_PATH"] = str(CHECKPOINT)


@pytest.fixture(autouse=True)
def fresh_checkpoint():
    """Each test uses a new in-memory database, so its checkpoint must start empty too."""
    CHECKPOINT.unlink(missing_ok=True)
    yield
    CHECKPOINT.unlink(missing_ok=True)
