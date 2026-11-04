"""
EBCP-Guard Application Configuration
=====================================
Loads all configuration from environment variables.
Never hardcode secrets — use .env (local) or a secrets manager (production).
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """
    Central settings class.  All values are read from environment variables
    or the .env file at startup.  No secrets are hardcoded here.
    """

    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        protected_namespaces=(),
    )

    # ------------------------------------------------------------------ #
    # Application
    # ------------------------------------------------------------------ #
    app_name: str = "EBCP-Guard"
    app_version: str = "0.1.0"
    app_env: Literal["development", "staging", "production"] = "development"
    debug: bool = False
    log_level: str = "INFO"

    # ------------------------------------------------------------------ #
    # FastAPI
    # ------------------------------------------------------------------ #
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_prefix: str = "/api/v1"
    cors_origins: list[str] = ["http://localhost:3000", "http://localhost:8080"]

    # ------------------------------------------------------------------ #
    # Database
    # ------------------------------------------------------------------ #
    database_url: str = Field(
        default="sqlite://ebcp_guard.db"
    )
    database_test_url: str = Field(
        default="sqlite://ebcp_guard_test.db"
    )

    # ------------------------------------------------------------------ #
    # Cryptographic Keys  (DEVELOPMENT DEFAULTS — always override via env)
    # ------------------------------------------------------------------ #
    master_key_hex: str = Field(
        default="0" * 64,
        description="256-bit master key as 64 hex chars — CHANGE IN PRODUCTION",
    )
    hmac_master_key_hex: str = Field(default="1" * 64)
    aes_master_key_hex: str = Field(default="2" * 64)
    audit_hmac_key_hex: str = Field(default="3" * 64)
    key_version: str = "v1"
    token_epoch_hours: int = 24

    # ------------------------------------------------------------------ #
    # AI Models
    # ------------------------------------------------------------------ #
    model_device: str = "cpu"
    hf_cache_dir: str = str(BASE_DIR / "models" / "checkpoints")
    gliner_model_id: str = "urchade/gliner_medium-v2.1"
    sensitivity_model_path: str = str(
        BASE_DIR / "models" / "checkpoints" / "sensitivity_classifier"
    )
    purpose_model_path: str = str(
        BASE_DIR / "models" / "checkpoints" / "purpose_classifier"
    )
    deberta_base_model: str = "microsoft/deberta-v3-small"
    model_confidence_threshold: float = 0.75
    low_confidence_action: str = "BLOCK"

    # ------------------------------------------------------------------ #
    # Policy
    # ------------------------------------------------------------------ #
    default_tenant_id: str = "default"
    fail_closed: bool = True
    rate_limit_per_minute: int = 100

    # ------------------------------------------------------------------ #
    # Security
    # ------------------------------------------------------------------ #
    authorized_decrypt_services: list[str] = ["payment_service", "fraud_service"]

    # ------------------------------------------------------------------ #
    # Risk Scoring Weights
    # ------------------------------------------------------------------ #
    risk_weight_sensitivity: float = 0.35   # α
    risk_weight_cumulative: float = 0.30    # β
    risk_weight_linkability: float = 0.20   # γ
    risk_weight_destination: float = 0.15   # δ

    # Risk thresholds → protection action
    risk_threshold_low: float = 0.30
    risk_threshold_medium: float = 0.55
    risk_threshold_high: float = 0.75

    # ------------------------------------------------------------------ #
    # Validators
    # ------------------------------------------------------------------ #
    @field_validator("master_key_hex", "hmac_master_key_hex",
                     "aes_master_key_hex", "audit_hmac_key_hex")
    @classmethod
    def validate_hex_key(cls, v: str) -> str:
        """Ensure key is a valid 64-character hex string (256 bits)."""
        if len(v) != 64:
            raise ValueError("Cryptographic key must be exactly 64 hex characters (256 bits)")
        try:
            bytes.fromhex(v)
        except ValueError:
            raise ValueError("Cryptographic key must be a valid hexadecimal string")
        return v

    def get_master_key_bytes(self) -> bytes:
        """Return master key as raw bytes."""
        return bytes.fromhex(self.master_key_hex)

    def get_hmac_master_key_bytes(self) -> bytes:
        return bytes.fromhex(self.hmac_master_key_hex)

    def get_aes_master_key_bytes(self) -> bytes:
        return bytes.fromhex(self.aes_master_key_hex)

    def get_audit_hmac_key_bytes(self) -> bytes:
        return bytes.fromhex(self.audit_hmac_key_hex)

    def is_development(self) -> bool:
        return self.app_env == "development"


@lru_cache()
def get_settings() -> Settings:
    """
    Return a cached Settings singleton.
    Cached so environment is parsed only once per process.
    """
    return Settings()
