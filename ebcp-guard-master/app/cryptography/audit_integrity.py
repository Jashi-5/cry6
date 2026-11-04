"""
EBCP-Guard SHA-256 Hash Chain + Merkle Tree Audit Integrity
=============================================================
Implements a tamper-evident audit trail using:

1. SHA-256 Hash Chain
   Each audit event includes the hash of the previous event:
   H_i = SHA256( H_{i-1} || canonical_event_i )

   Any modification to event_k changes H_k, which cascades
   forward through all subsequent hashes — making tampering detectable
   during verification.

2. Merkle Tree
   Batches of events are organized into a binary Merkle tree.
   The root hash summarizes all events in the batch.
   Individual events can be proven to belong to the batch via
   Merkle inclusion proofs.

IMPORTANT SECURITY CLARIFICATION:
  Hash chains are tamper-EVIDENT, not tamper-PROOF.
  An attacker who controls the storage layer could re-compute
  the entire chain after modification. For stronger guarantees:
  - Store Merkle roots externally (blockchain, notarization service).
  - Use independently protected checkpoints.
  The current implementation provides strong evidence of tampering
  when the trusted genesis/checkpoint hash is preserved externally.

SECURITY NOTE:
  Audit events must NEVER contain original PII.
  Only entity type labels, risk scores, protection actions,
  request IDs, and safe metadata are included.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
from datetime import datetime, timezone
from typing import Any


GENESIS_HASH = "0" * 64  # Sentinel for the first event in a chain


def _canonical_json(data: dict[str, Any]) -> bytes:
    """
    Serialize a dictionary to canonical JSON (sorted keys, no whitespace).
    This ensures consistent hashing regardless of key insertion order.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def compute_event_hash(
    previous_hash: str,
    event_data: dict[str, Any],
    key: bytes | None = None,
) -> str:
    """
    Compute the chain hash for a single audit event:
    H_i = HMAC-SHA256( key, H_{i-1} || canonical_event_i )

    Stored audit events must always pass key: without it the hash is plain SHA-256,
    which anyone with database access can recompute after changing history.

    Args:
        previous_hash: Hex-encoded hash of the preceding event (or GENESIS_HASH).
        event_data:    Safe metadata dict for the current event (no PII).

    Returns:
        Hex-encoded SHA-256 hash of the concatenated input.
    """
    previous_bytes = bytes.fromhex(previous_hash)
    event_bytes = _canonical_json(event_data)
    combined = previous_bytes + event_bytes
    if key is not None:
        return hmac.new(key, combined, hashlib.sha256).hexdigest()
    return hashlib.sha256(combined).hexdigest()


def verify_chain(
    events: list[dict[str, Any]],
    genesis_hash: str = GENESIS_HASH,
    key: bytes | None = None,
) -> tuple[bool, int | None, str | None]:
    """
    Verify the integrity of an ordered sequence of audit events.

    Each event dict must contain:
        - "previous_hash": hash of the preceding event.
        - "current_hash":  stored hash for this event.
        - "safe_metadata": safe event content.
        - "sequence_number": ordering key.

    Args:
        events:       Ordered list of audit event dicts (ascending sequence).
        genesis_hash: Expected hash for the very first event's previous_hash.
        key:          HMAC key the chain was written with.

    Returns:
        Tuple of (is_valid, first_failed_sequence, first_failed_event_id).
        is_valid is True only if ALL events pass verification.
    """
    if not events:
        return True, None, None

    expected_prev = genesis_hash

    for event in events:
        stored_prev = event.get("previous_hash", "")
        stored_current = event.get("current_hash", "")
        metadata = event.get("safe_metadata", {})
        seq = event.get("sequence_number", -1)
        event_id = event.get("event_id", "UNKNOWN")

        # Check previous_hash chain link
        if stored_prev != expected_prev:
            return False, seq, event_id

        # Recompute current hash from stored data
        recomputed = compute_event_hash(stored_prev, metadata, key)
        if not hmac.compare_digest(recomputed, stored_current):
            return False, seq, event_id

        expected_prev = stored_current

    return True, None, None


# ------------------------------------------------------------------ #
# Merkle Tree
# ------------------------------------------------------------------ #

def _merkle_leaf_hash(event_hash: str) -> str:
    """Compute the Merkle leaf hash for an event hash."""
    return hashlib.sha256(b"leaf:" + event_hash.encode("utf-8")).hexdigest()


def _merkle_parent_hash(left: str, right: str) -> str:
    """Compute a Merkle parent node hash from two child hashes."""
    combined = (left + right).encode("utf-8")
    return hashlib.sha256(b"node:" + combined).hexdigest()


def build_merkle_tree(event_hashes: list[str]) -> tuple[str, list[list[str]]]:
    """
    Build a binary Merkle tree from a list of event hashes.

    Duplicate the last element if the number is odd (standard approach).

    Args:
        event_hashes: List of event current_hashes.

    Returns:
        Tuple of (root_hash, tree_levels) where tree_levels[0] is the
        leaf level and tree_levels[-1] contains only the root.
    """
    if not event_hashes:
        return GENESIS_HASH, []

    leaves = [_merkle_leaf_hash(h) for h in event_hashes]
    levels = [leaves]
    current = leaves

    while len(current) > 1:
        if len(current) % 2 == 1:
            current = current + [current[-1]]  # Duplicate last node

        parent_level = []
        for i in range(0, len(current), 2):
            parent = _merkle_parent_hash(current[i], current[i + 1])
            parent_level.append(parent)
        levels.append(parent_level)
        current = parent_level

    return current[0], levels


def generate_merkle_proof(
    event_index: int,
    event_hashes: list[str],
) -> list[dict[str, str]]:
    """
    Generate a Merkle inclusion proof for the event at the given index.

    Returns a list of sibling hashes needed to reconstruct the root:
        [{"hash": "...", "position": "left" | "right"}, ...]

    The verifier can confirm event membership without storing all events.
    """
    _, levels = build_merkle_tree(event_hashes)
    if not levels:
        return []

    proof: list[dict[str, str]] = []
    idx = event_index

    for level in levels[:-1]:  # Exclude root level
        if len(level) % 2 == 1:
            level = level + [level[-1]]

        if idx % 2 == 0:
            sibling_idx = idx + 1
            position = "right"
        else:
            sibling_idx = idx - 1
            position = "left"

        if sibling_idx < len(level):
            proof.append({"hash": level[sibling_idx], "position": position})

        idx //= 2

    return proof


def verify_merkle_proof(
    event_hash: str,
    proof: list[dict[str, str]],
    expected_root: str,
) -> bool:
    """
    Verify that an event hash is included in a Merkle tree
    using the provided proof path.

    Args:
        event_hash:    current_hash of the event to verify.
        proof:         List of sibling hashes from generate_merkle_proof.
        expected_root: Trusted Merkle root to verify against.

    Returns:
        True if the proof is valid and the event is included in the tree.
    """
    current = _merkle_leaf_hash(event_hash)

    for step in proof:
        sibling = step["hash"]
        position = step["position"]

        if position == "right":
            current = _merkle_parent_hash(current, sibling)
        else:
            current = _merkle_parent_hash(sibling, current)

    return current == expected_root


# ------------------------------------------------------------------ #
# Audit event builder helpers
# ------------------------------------------------------------------ #

def build_safe_audit_metadata(
    request_id: str | None,
    tenant_id: str,
    synthetic_customer_id: str | None,
    event_type: str,
    entity_types: list[str],
    sensitivity_class: str | None,
    protection_action: str | None,
    risk_score: float | None,
    model_versions: dict[str, str] | None = None,
) -> dict[str, Any]:
    """
    Build a safe audit metadata dictionary.
    Only non-PII identifiers and statistical data are included.

    No original sensitive values, no email addresses, no names.
    """
    return {
        "request_id": request_id,
        "tenant_id": tenant_id,
        "synthetic_customer_id": synthetic_customer_id,
        "event_type": event_type,
        "entity_types_detected": entity_types,          # TYPE labels only
        "entity_count": len(entity_types),
        "sensitivity_class": sensitivity_class,
        "protection_action": protection_action,
        "risk_score": risk_score,
        "model_versions": model_versions or {},
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
    }
