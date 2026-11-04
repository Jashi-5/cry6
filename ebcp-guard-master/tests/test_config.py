"""Fix 4: deployed environments refuse the public placeholder keys."""

import secrets

import pytest

from app.config import Settings

KEY_FIELDS = ["master_key_hex", "hmac_master_key_hex", "aes_master_key_hex", "audit_hmac_key_hex"]


def fresh_keys():
    return {name: secrets.token_hex(32) for name in KEY_FIELDS}


@pytest.mark.parametrize("env", ["production", "staging"])
def test_placeholder_keys_refused_when_deployed(env):
    with pytest.raises(ValueError, match="placeholder keys"):
        Settings(_env_file=None, app_env=env, **{name: "1" * 64 for name in KEY_FIELDS})


@pytest.mark.parametrize("weak", KEY_FIELDS)
def test_one_placeholder_key_is_enough_to_refuse(weak):
    with pytest.raises(ValueError, match=weak):
        Settings(_env_file=None, app_env="production", **{**fresh_keys(), weak: "2" * 64})


def test_error_never_shows_key_values():
    keys = {**fresh_keys(), "aes_master_key_hex": "a" * 64}
    with pytest.raises(ValueError) as caught:
        Settings(_env_file=None, app_env="production", **keys)
    assert keys["hmac_master_key_hex"] not in str(caught.value)


def test_generated_keys_accepted_in_production():
    assert Settings(_env_file=None, app_env="production", **fresh_keys()).app_env == "production"


def test_placeholders_still_allowed_in_development():
    assert Settings(_env_file=None, app_env="development", **{name: "1" * 64 for name in KEY_FIELDS})
