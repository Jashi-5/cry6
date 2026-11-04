"""
Live adversarial test: attacks a real running EBCP-Guard server over HTTP.

Unlike /simulate-attack, nothing here calls the defenses in-process with fixed values.
It starts its own server on a throwaway database, sends randomly generated
identifiers through the real API, tampers with the real audit table and restarts
the server. No external network calls. Never feed it real customer data.

Usage:  venv/Scripts/python scripts/live_attack_test.py [--seed N] [--port 8003]
HELD = the defense worked. BROKEN = the attack succeeded. Exit code 1 if anything is BROKEN.
"""
import argparse
import base64
import hashlib
import json
import os
import random
import re
import secrets
import shutil
import sqlite3
import string
import subprocess
import sys
import tempfile
import time
import urllib.parse
from collections import Counter
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.stdout.reconfigure(encoding="utf-8")

parser = argparse.ArgumentParser()
parser.add_argument("--seed", type=int, default=int(time.time()))
parser.add_argument("--port", type=int, default=8003)
parser.add_argument("--per-case", type=int, default=5)
args = parser.parse_args()
rng = random.Random(args.seed)
BASE = f"http://127.0.0.1:{args.port}"
API = f"{BASE}/api/v1"
sent_values: set[str] = set()
results: list[tuple[str, bool, str]] = []

# Fresh keys for the throwaway server only.
SERVICES = {
    "token_service": ["*"],
    "payment_service": ["decrypt_bank", "other_bank"],
    "fraud_service": ["unrelated_bank"],
    "reporting_service": ["*"],
}
KEYS = {name: secrets.token_urlsafe(32) for name in SERVICES}


def key(name: str) -> dict:
    return {"X-API-Key": KEYS[name]}


def service_keys_env() -> str:
    return json.dumps({
        name: {"key_sha256": hashlib.sha256(KEYS[name].encode()).hexdigest(), "tenants": tenants}
        for name, tenants in SERVICES.items()
    })


def record(name: str, held: bool, evidence: str) -> None:
    results.append((name, held, evidence))
    print(f"[{'HELD  ' if held else 'BROKEN'}] {name}\n         {evidence}")


# ---------------------------- generated identifiers ---------------------------- #
def digits(n: int) -> str:
    return "".join(rng.choices(string.digits, k=n))


def letters(n: int) -> str:
    return "".join(rng.choices(string.ascii_uppercase, k=n))


def luhn_card() -> str:
    body = rng.choice("45") + ("" if False else digits(14))
    if body[0] == "5":
        body = "5" + rng.choice("12345") + body[2:]
    total = 0
    for i, ch in enumerate(reversed(body)):
        d = int(ch)
        if i % 2 == 0:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return body + str((10 - total % 10) % 10)


GENERATORS = {
    "EMAIL": lambda: f"{letters(8).lower()}.{digits(4)}@example.com",
    "PAN": lambda: letters(5) + digits(4) + letters(1),
    "AADHAAR": lambda: rng.choice("23456789") + digits(11),
    "CARD_NUMBER": luhn_card,
    "PHONE": lambda: rng.choice("6789") + digits(9),
    "ACCOUNT_NUMBER": lambda: "1" + digits(rng.choice([10, 12, 13])),
    "UPI_ID": lambda: f"{letters(7).lower()}{digits(3)}@oksbi",
    "IFSC": lambda: letters(4) + "0" + letters(2) + digits(4),
}
NUMERIC = {"AADHAAR", "CARD_NUMBER", "PHONE", "ACCOUNT_NUMBER"}


def new_value(entity: str) -> str:
    value = GENERATORS[entity]()
    sent_values.add(value)
    return value


# ------------------------------- server lifecycle ------------------------------- #
tmp = Path(tempfile.mkdtemp(prefix="ebcp_live_"))
db_path = tmp / "live.db"
log_path = tmp / "server.log"
server: subprocess.Popen | None = None


def start_server() -> None:
    global server
    env = {
        **os.environ,
        "DATABASE_URL": f"sqlite://{db_path.as_posix()}",
        "AUDIT_CHECKPOINT_PATH": str(tmp / "checkpoint.json"),
        "SERVICE_API_KEYS": service_keys_env(),
        "PYTHONIOENCODING": "utf-8",
    }
    log = open(log_path, "ab")
    server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(args.port)],
        cwd=ROOT, env=env, stdout=log, stderr=log,
    )
    for _ in range(120):
        try:
            if httpx.get(f"{API}/health", timeout=2).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.5)
    raise RuntimeError(f"server did not start; see {log_path}")


def stop_server() -> None:
    if server and server.poll() is None:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(server.pid), "/T", "/F"], capture_output=True)
        else:
            server.kill()
        server.wait(10)
        time.sleep(1)


client = httpx.Client(timeout=30)


def protect(payload: dict, destination: str, tenant: str = "live_bank", customer: str | None = "new") -> dict:
    if customer == "new":
        customer = f"CUST-{digits(10)}"
    body = {"payload": payload, "endpoint": "/api/v1/customers", "destination_service": destination, "tenant_id": tenant}
    if customer:
        body["synthetic_customer_id"] = customer
    res = client.post(f"{API}/protect", json=body)
    if res.status_code != 200:
        return {"protection_decision": f"HTTP{res.status_code}", "protected_payload": {}, "entity_decisions": []}
    return res.json()


# ---------------------------- 1. real redaction leaks ---------------------------- #
def shape_cases(entity: str, v: str) -> dict[str, tuple[dict, str]]:
    cases = {
        "string field": ({"field": v}, v),
        "named field": ({entity.lower(): v, "account": v}, v),
        "nested object": ({"customer": {"profile": {"field": v}}}, v),
        "list of strings": ({"items": [v, "other"]}, v),
        "sentence": ({"note": f"Please update the record for {v} today."}, v),
        "list inside list": ({"rows": [[v, "other"]]}, v),
        "as a JSON key": ({"lookup": {v: "active"}}, v),
    }
    if entity in NUMERIC:
        cases["JSON number"] = ({"field": int(v)}, v)
        cases["list of numbers"] = ({"items": [int(v)]}, v)
    return cases


def test_redaction() -> None:
    for destination in ("third_party_analytics", "internal_analytics", "internal_payment"):
        by_shape: dict[str, Counter] = {}
        leaked_types: dict[str, set] = {}
        decisions: Counter = Counter()
        for entity in GENERATORS:
            for _ in range(args.per_case):
                v = new_value(entity)
                for shape, (payload, needle) in shape_cases(entity, v).items():
                    out = protect(payload, destination)
                    decisions[out["protection_decision"]] += 1
                    c = by_shape.setdefault(shape, Counter())
                    c["total"] += 1
                    if needle in json.dumps(out["protected_payload"]):
                        c["leaked"] += 1
                        leaked_types.setdefault(shape, set()).add(entity)
        total_leaks = sum(c["leaked"] for c in by_shape.values())
        total = sum(c["total"] for c in by_shape.values())
        detail = "; ".join(f"{s}: {c['leaked']}/{c['total']}" for s, c in by_shape.items())
        record(f"Raw identifiers removed before reaching {destination}", total_leaks == 0,
               f"{total_leaks}/{total} leaked | {detail} | decisions {dict(decisions)}")
        print("         leaked types:", {k: sorted(v) for k, v in leaked_types.items()})


def test_evasion() -> None:
    def spaced(v, n=4):
        return " ".join(v[i:i + n] for i in range(0, len(v), n))

    variants = {
        "lowercase PAN": lambda: new_value("PAN").lower(),
        "card with spaces": lambda: spaced(new_value("CARD_NUMBER")),
        "card with hyphens": lambda: spaced(new_value("CARD_NUMBER")).replace(" ", "-"),
        "Aadhaar with spaces": lambda: spaced(new_value("AADHAAR")),
        "phone +91 prefix": lambda: "+91" + new_value("PHONE"),
        "phone 5-5 spaced": lambda: (lambda p: f"{p[:5]} {p[5:]}")(new_value("PHONE")),
        "UPPERCASE email": lambda: new_value("EMAIL").upper(),
        "URL-encoded email": lambda: urllib.parse.quote(new_value("EMAIL"), safe=""),
        "email [at] [dot]": lambda: new_value("EMAIL").replace("@", "[at]").replace(".", "[dot]"),
        "base64 PAN": lambda: base64.b64encode(new_value("PAN").encode()).decode(),
        "PAN with hyphens": lambda: (lambda p: f"{p[:5]}-{p[5:9]}-{p[9]}")(new_value("PAN")),
    }
    rows, leaks, total = [], 0, 0
    for name, make in variants.items():
        hit = 0
        for _ in range(args.per_case * 2):
            v = make()
            sent_values.add(v)
            out = protect({"field": v}, "third_party_analytics")
            hit += v in json.dumps(out["protected_payload"])
        rows.append(f"{name}: {hit}/{args.per_case * 2}")
        leaks += hit
        total += args.per_case * 2
    record("Obfuscated identifiers still caught", leaks == 0, f"{leaks}/{total} passed through unchanged | " + "; ".join(rows))


# --------------------------------- 2. tokenization --------------------------------- #
def tokenize_as(service: str | None, values: list[str], entity: str, tenant: str, purpose: str) -> httpx.Response:
    body = {"values": [{"entity_type": entity, "value": v} for v in values], "tenant_id": tenant, "purpose": purpose}
    return client.post(f"{API}/tokenize", json=body, headers=key(service) if service else {})


def tokens(values, entity, tenant, purpose) -> list[str]:
    res = tokenize_as("token_service", values, entity, tenant, purpose)
    res.raise_for_status()
    return [t["token"] for t in res.json()["tokens"]]


def test_tokens() -> None:
    values = [new_value("EMAIL") for _ in range(200)]
    a_pay = tokens(values, "EMAIL", "bank_a", "PAYMENT_PROCESSING")
    b_pay = tokens(values, "EMAIL", "bank_b", "PAYMENT_PROCESSING")
    a_ana = tokens(values, "EMAIL", "bank_a", "ANALYTICS")
    links = len(set(a_pay) & set(b_pay)) + len(set(a_pay) & set(a_ana))
    record("Same customers cannot be linked across tenants or purposes", links == 0,
           f"{links} matching tokens across 200 customers in 3 scopes")

    # The attacker holds a stolen token and a list of likely emails, but no key.
    target, stolen = values[0], a_pay[0]
    dictionary = [new_value("EMAIL") for _ in range(999)] + [target]
    rng.shuffle(dictionary)
    res = tokenize_as(None, dictionary, "EMAIL", "bank_a", "PAYMENT_PROCESSING")
    recovered = res.status_code == 200 and stolen in res.text
    record("Stolen token cannot be reversed with /tokenize without an API key", not recovered, f"HTTP {res.status_code}, recovered: {recovered}")

    bad = client.post(f"{API}/tokenize", headers={"X-API-Key": "guessed-key"},
                      json={"values": [{"entity_type": "EMAIL", "value": target}], "tenant_id": "bank_a", "purpose": "PAYMENT_PROCESSING"})
    record("Invalid API key is refused", bad.status_code == 401, f"HTTP {bad.status_code}")

    scoped = tokenize_as("payment_service", [target], "EMAIL", "bank_a", "PAYMENT_PROCESSING")
    record("A valid key cannot be used for a tenant it does not cover", scoped.status_code == 403, f"HTTP {scoped.status_code}")

    key_re = re.compile(r"^(HMAC_MASTER_KEY_HEX|AES_MASTER_KEY_HEX|AUDIT_HMAC_KEY_HEX)=(.*)$", re.M)
    published = dict(key_re.findall((ROOT / ".env.example").read_text(encoding="utf-8")))
    same = published == dict(key_re.findall((ROOT / ".env").read_text(encoding="utf-8")))
    server = tokenize_as("token_service", [target], "EMAIL", "bank_a", "ANALYTICS").json()
    # Compute from the published keys, as an outsider would.
    code = (
        "import sys; from app.cryptography.tokenization import generate_token as g;"
        "print(g(sys.argv[1], 'EMAIL', 'bank_a', 'ANALYTICS', sys.argv[2])[0])"
    )
    run_env = {**os.environ, **published}
    offline = subprocess.run([sys.executable, "-c", code, target, server["epoch_id"]], cwd=ROOT, capture_output=True, text=True, env=run_env).stdout.strip()
    forged = offline == server["tokens"][0]["token"]
    record("Tokens cannot be computed offline from published repo keys", not forged,
           f"server keys identical to .env.example: {same}; token computed from published keys matches server: {forged}")

    boot = "from app.config import get_settings; from app.cryptography.key_manager import get_key_manager; get_key_manager(); print(get_settings().app_env)"
    with_published = subprocess.run([sys.executable, "-c", boot], cwd=ROOT, capture_output=True, text=True,
                                    env={**os.environ, **published, "APP_ENV": "production", "DEBUG": "false"})
    refused = with_published.returncode != 0
    record("Production mode refuses the published development keys", refused,
           "refused at startup" if refused else "started with APP_ENV=production and the .env.example keys")
    fresh = {k: secrets.token_hex(32) for k in published} | {"MASTER_KEY_HEX": secrets.token_hex(32)}
    with_fresh = subprocess.run([sys.executable, "-c", boot], cwd=ROOT, capture_output=True, text=True,
                                env={**os.environ, **fresh, "APP_ENV": "production", "DEBUG": "false"})
    record("Production mode starts with properly generated keys", with_fresh.returncode == 0, (with_fresh.stderr.strip()[-200:] or with_fresh.stdout.strip()))


# ------------------------------------ 3. decrypt ------------------------------------ #
def audit_count(tenant: str) -> dict:
    return client.post(f"{API}/verify-audit", json={"tenant_id": tenant}, headers=key("token_service")).json()


def test_decrypt() -> None:
    from app.cryptography.encryption import encrypt_value

    secret = new_value("ACCOUNT_NUMBER")
    tenant = "decrypt_bank"
    # Same as ciphertext stolen from storage or logs.
    package = encrypt_value(secret, "ACCOUNT_NUMBER", tenant, "PAYMENT_PROCESSING").cipher_package_b64

    def attempt(service=None, ciphertext=package, t=tenant, claim=None):
        body = {"cipher_id": "stolen", "ciphertext_b64": ciphertext, "tenant_id": t}
        if claim:
            body["requesting_service"] = claim
        return client.post(f"{API}/decrypt", json=body, headers=key(service) if service else {})

    before = audit_count(tenant)["checked_events"]
    spoof = attempt(claim="payment_service")
    record("Attacker cannot decrypt by claiming to be an authorized service", secret not in spoof.text,
           f"HTTP {spoof.status_code} with requesting_service=payment_service and no key")
    plain = attempt()
    record("No API key means no decryption", plain.status_code == 401 and secret not in plain.text, f"HTTP {plain.status_code}")
    other_service = attempt("reporting_service")
    record("A valid key for a service without decrypt rights is refused", other_service.status_code == 403 and secret not in other_service.text, f"HTTP {other_service.status_code}")
    wrong_tenant = attempt("fraud_service")
    record("A decrypt service cannot act for a tenant it does not cover", wrong_tenant.status_code == 403 and secret not in wrong_tenant.text, f"HTTP {wrong_tenant.status_code}")
    mismatch = attempt("reporting_service", claim="payment_service")
    record("A key cannot borrow another service's name", mismatch.status_code == 403 and secret not in mismatch.text, f"HTTP {mismatch.status_code}")

    after = audit_count(tenant)["checked_events"]
    record("Denied decryption attempts are audited", after - before == 5, f"{after - before} audit events for 5 denied attempts")

    legit = attempt("payment_service")
    record("Authorized service with its own key can still decrypt", legit.status_code == 200 and legit.json().get("decrypted_value") == secret, f"HTTP {legit.status_code}")

    other = attempt("payment_service", t="other_bank")
    record("Ciphertext from one tenant cannot be decrypted under another", secret not in other.text, f"HTTP {other.status_code}")

    raw = bytearray(base64.b64decode(package))
    statuses: Counter = Counter()
    recovered = 0
    for _ in range(100):
        bad = bytearray(raw)
        bad[rng.randrange(len(bad))] ^= 1 << rng.randrange(8)
        res = attempt("payment_service", base64.b64encode(bytes(bad)).decode())
        statuses[res.status_code] += 1
        recovered += res.status_code == 200
    record("Any flipped ciphertext bit is rejected", recovered == 0 and 500 not in statuses, f"100 single-bit flips: statuses {dict(statuses)}")


# ------------------------------------- 4. audit ------------------------------------- #
def make_events(tenant: str, n: int) -> None:
    for _ in range(n):
        protect({"field": new_value("EMAIL")}, "internal_analytics", tenant=tenant)


def rows(conn, tenant):
    cur = conn.execute("SELECT event_id, safe_metadata, previous_hash, current_hash FROM audit_events WHERE tenant_id=? ORDER BY sequence_number", (tenant,))
    return cur.fetchall()


def test_audit() -> None:
    from app.cryptography.audit_integrity import GENESIS_HASH, compute_event_hash

    clean_tenant = "audit_clean"
    make_events(clean_tenant, 10)
    v = audit_count(clean_tenant)
    record("Untouched audit chain verifies", v["verified"] and v["checked_events"] == 10, str({k: v[k] for k in ("verified", "checked_events")}))

    conn = sqlite3.connect(db_path, timeout=10)
    try:
        # Naive edit of one record
        t = "audit_edit"
        make_events(t, 10)
        event_id, meta, *_ = rows(conn, t)[4]
        changed = json.loads(meta)
        changed["protection_action"] = "ALLOW"
        conn.execute("UPDATE audit_events SET safe_metadata=? WHERE event_id=?", (json.dumps(changed), event_id))
        conn.commit()
        v = audit_count(t)
        record("Direct edit of an audit record is detected", not v["verified"], f"verified={v['verified']}, first failure at seq {v['first_failed_sequence']}")

        # Edit, then recompute every later hash. The attacker has database access but no audit key.
        t = "audit_rewrite"
        make_events(t, 10)
        prev = GENESIS_HASH
        for i, (event_id, meta, *_) in enumerate(rows(conn, t)):
            data = json.loads(meta)
            if i == 4:
                data["protection_action"] = "ALLOW"
            new_hash = compute_event_hash(prev, data)
            conn.execute("UPDATE audit_events SET safe_metadata=?, previous_hash=?, current_hash=? WHERE event_id=?", (json.dumps(data), prev, new_hash, event_id))
            prev = new_hash
        conn.commit()
        v = audit_count(t)
        record("Rewriting the audit history with recomputed hashes is detected", not v["verified"],
               f"verified={v['verified']} after changing event 5 to ALLOW without the audit key")

        # Delete newest events
        t = "audit_truncate"
        make_events(t, 10)
        for event_id, *_ in rows(conn, t)[-4:]:
            conn.execute("DELETE FROM audit_events WHERE event_id=?", (event_id,))
        conn.commit()
        v = audit_count(t)
        record("Deleting the newest audit events is detected", not v["verified"], f"verified={v['verified']}, checked_events={v['checked_events']} of 10 written")

        # Delete newest events, then let normal traffic build on the shortened chain
        make_events(t, 6)
        v = audit_count(t)
        record("New traffic cannot hide deleted audit events", not v["verified"], f"verified={v['verified']}, checked_events={v['checked_events']} after 6 more real events")

        # Delete from the middle
        t = "audit_delete"
        make_events(t, 10)
        conn.execute("DELETE FROM audit_events WHERE event_id=?", (rows(conn, t)[4][0],))
        conn.commit()
        v = audit_count(t)
        record("Deleting a middle audit event is detected", not v["verified"], f"verified={v['verified']}, first failure at seq {v['first_failed_sequence']}")
    finally:
        conn.close()


# ----------------------------------- 5. cumulative ----------------------------------- #
def slow_leak(values: list[str], customer_for_step) -> list[tuple[float, str]]:
    steps = []
    for i, value in enumerate(values):
        out = protect({"field": value}, "third_party_analytics", customer=customer_for_step(i))
        steps.append((out.get("risk_score", -1), out["protection_decision"]))
    return steps


def fmt(steps):
    return " -> ".join(f"{r:.2f}/{d}" for r, d in steps)


def test_cumulative() -> tuple[str, list]:
    # Each trial replays identical values, so only the customer id differs between paths.
    entities = ["EMAIL", "PHONE", "IFSC", "ACCOUNT_NUMBER", "PAN", "AADHAAR"]
    trials = 10
    finals = {"tracked": [], "rotated": [], "omitted": []}
    example = {}
    customer = ""
    for _ in range(trials):
        values = [new_value(e) for e in entities]
        customer = f"CUST-{digits(10)}"
        paths = {
            "tracked": slow_leak(values, lambda i: customer),
            "rotated": slow_leak(values, lambda i: f"CUST-{digits(10)}"),
            "omitted": slow_leak(values, lambda i: None),
        }
        for name, steps in paths.items():
            finals[name].append(steps[-1][0])
        example = paths
    tracked = example["tracked"]
    mean = {k: sum(v) / trials for k, v in finals.items()}
    record("Risk rises across six single-field requests for one customer", mean["tracked"] > tracked[0][0], fmt(tracked))
    for path, label in (("rotated", "changing customer id"), ("omitted", "omitting customer id")):
        record(f"Slow leak cannot avoid tracking by {label}", mean[path] >= mean["tracked"] - 0.02,
               f"mean final risk over {trials} paired trials: tracked {mean['tracked']:.2f}, {path} {mean[path]:.2f} | last trial {fmt(example[path])}")

    res = client.get(f"{API}/exposure/{customer}")
    record("Another caller cannot read a customer's exposure history", res.status_code == 401, f"HTTP {res.status_code} with no key")
    # These events belong to tenant live_bank, which payment_service does not cover.
    scoped = client.get(f"{API}/exposure/{customer}", headers=key("payment_service")).json()
    owner = client.get(f"{API}/exposure/{customer}", headers=key("token_service")).json()
    record("A key only sees exposure history for its own tenants", scoped["total_events"] == 0 and owner["total_events"] == len(tracked),
           f"other-tenant key sees {scoped['total_events']} events; all-tenant key sees {owner['total_events']}")
    return customer, tracked


# ---------------------------------- 6. restart / rest ---------------------------------- #
def test_restart(customer: str, tracked_count: int) -> None:
    tenant = "audit_restart"
    make_events(tenant, 5)
    before = audit_count(tenant)
    stop_server()
    start_server()
    res = client.get(f"{API}/exposure/{customer}", headers=key("token_service")).json()
    record("Exposure history survives a server restart", res["total_events"] >= tracked_count,
           f"{tracked_count} events before restart, {res['total_events']} after")
    make_events(tenant, 3)
    after = audit_count(tenant)
    record("Audit chain stays valid across a server restart", after["verified"] and after["checked_events"] == 8,
           f"before: verified={before['verified']} ({before['checked_events']}); after: verified={after['verified']} ({after['checked_events']} of 8), first failure seq {after['first_failed_sequence']}")


# ------------------------------- 7. deployed gateway ------------------------------- #
def test_production_gateway() -> None:
    """A second server in production mode, because development leaves /protect open for the demo page."""
    port = args.port + 1
    prod_api = f"http://127.0.0.1:{port}/api/v1"
    prod_keys = ("MASTER_KEY_HEX", "HMAC_MASTER_KEY_HEX", "AES_MASTER_KEY_HEX", "AUDIT_HMAC_KEY_HEX")
    env = {
        **os.environ,
        **{name: secrets.token_hex(32) for name in prod_keys},
        "APP_ENV": "production",
        "DEBUG": "false",
        "DATABASE_URL": f"sqlite://{(tmp / 'prod.db').as_posix()}",
        "AUDIT_CHECKPOINT_PATH": str(tmp / "prod_checkpoint.json"),
        "SERVICE_API_KEYS": service_keys_env(),
        "PYTHONIOENCODING": "utf-8",
    }
    log = open(tmp / "prod.log", "ab")
    prod = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(port)],
                            cwd=ROOT, env=env, stdout=log, stderr=log)
    try:
        for _ in range(120):
            try:
                if httpx.get(f"{prod_api}/health", timeout=2).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.5)

        def call(path, service=None, tenant="bank_a", value=None):
            body = {"payload": {"field": value or new_value("PHONE")}, "tenant_id": tenant,
                    "destination_service": "third_party_analytics", "synthetic_customer_id": f"CUST-{digits(10)}"}
            return client.post(f"{prod_api}{path}", json=body, headers=key(service) if service else {})

        statuses = {
            "/protect": call("/protect").status_code,
            "/analyze": call("/analyze").status_code,
            "/verify-audit": client.post(f"{prod_api}/verify-audit", json={"tenant_id": "bank_a"}).status_code,
            "/models/status": client.get(f"{prod_api}/models/status").status_code,
        }
        record("Deployed gateway refuses every sensitive endpoint without a key", set(statuses.values()) == {401}, str(statuses))

        record("Deployed gateway still works with a valid key", call("/protect", "token_service").status_code == 200 and call("/analyze", "token_service").status_code == 200, "HTTP 200")
        scoped = call("/protect", "fraud_service").status_code
        record("Deployed gateway refuses a key for another tenant", scoped == 403, f"HTTP {scoped}")

        # The original attack: a keyed service tokenizes a victim's value; an outsider guesses with no key.
        victim = new_value("PHONE")
        victim_out = call("/protect", "token_service", value=victim).text
        found = re.search(r"[A-Z_]+_[0-9a-f]{64}", victim_out)
        record("Test precondition: the deployed gateway produced a token to attack", bool(found), found.group(0)[:16] + "..." if found else "no token")
        guesses = [new_value("PHONE") for _ in range(20)] + [victim]
        answers = [call("/protect", value=g) for g in guesses]
        hits = sum(bool(found) and found.group(0) in r.text for r in answers)
        record("Stolen token cannot be reversed through /protect on a deployed gateway", hits == 0,
               f"{hits} of {len(guesses)} guesses matched; statuses {dict(Counter(r.status_code for r in answers))}")
    finally:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(prod.pid), "/T", "/F"], capture_output=True)
        else:
            prod.kill()
        prod.wait(10)
        log.close()
        time.sleep(1)


def test_at_rest() -> None:
    needles = [v.encode() for v in sent_values if len(v) >= 8]
    def scan(path):
        data = path.read_bytes()
        return sum(n in data for n in needles)
    db_hits = sum(scan(p) for p in tmp.glob("live.db*"))
    log_hits = scan(log_path)
    record("No generated identifier stored in database files", db_hits == 0, f"{db_hits} of {len(needles)} values found")
    record("No generated identifier written to server logs", log_hits == 0, f"{log_hits} of {len(needles)} values found")


def main() -> int:
    print(f"seed={args.seed}  server={BASE}  throwaway data={tmp}\n")
    start_server()
    try:
        test_redaction()
        test_evasion()
        test_tokens()
        test_decrypt()
        test_audit()
        customer, tracked = test_cumulative()
        test_restart(customer, len(tracked))
        test_production_gateway()
        test_at_rest()
    finally:
        stop_server()
        client.close()
    broken = [r for r in results if not r[1]]
    print(f"\nSUMMARY: {len(results) - len(broken)} held, {len(broken)} broken, {len(results)} total")
    for name, _, _ in broken:
        print("  BROKEN:", name)
    shutil.rmtree(tmp, ignore_errors=True)
    return 1 if broken else 0


if __name__ == "__main__":
    sys.exit(main())
