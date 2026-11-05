# EBCP-Guard: Exposure-Budgeted Cryptographic Protection Framework

**AI-Powered Context-Aware Sensitive Data Leakage Prevention in API Traffic and Application Logs**

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Cryptography](https://img.shields.io/badge/Cryptography-AES--256--GCM%20%7C%20HMAC--SHA--256-brightgreen.svg)](https://cryptography.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests Passing](https://img.shields.io/badge/tests-29%2F29%20passed-success.svg)]()

---

## 1. Executive Overview

**EBCP-Guard** is a research-grade cybersecurity privacy gateway and Data Loss Prevention (DLP) framework designed for banking, fintech, and financial services.

Traditional DLP tools rely on static regex pattern matching or isolated dictionary lookups. In modern distributed financial architectures, these conventional mechanisms fail across three critical threat vectors:
1. **Context Blindness**: They treat sensitive entities identically regardless of operational intent or destination trust (e.g. failing to differentiate authorized payment settlement from secondary marketing telemetry).
2. **Cumulative Exposure ("Slow-Leak" Attacks)**: An attacker querying individual data fields (email, phone, account number, PAN) across separate API requests bypasses single-request thresholds while reconstructing complete customer identities.
3. **Identity Correlation & Rainbow Tables**: Using deterministic or unsalted hashes allows attackers to correlate customer transactions across tenants and conduct precomputed dictionary attacks.

**EBCP-Guard eliminates these vulnerabilities by uniting AI/NLP sensitivity classification, operational purpose recognition, cumulative exposure budgeting, and purpose-scoped hybrid cryptography.**

---

## 2. System Architecture & Data Flow

```
                      Ingress API Request / Application Log
                                        │
                                        ▼
                   ┌─────────────────────────────────────────┐
                   │   Input Normalization & Schema Parsing  │
                   └────────────────────┬────────────────────┘
                                        │
                                        ▼
                   ┌─────────────────────────────────────────┐
                   │     Hybrid Sensitive Data Detection     │ ◄── Anchored Regex + Validators
                   └────────────────────┬────────────────────┘     (PAN, Aadhaar, IFSC, UPI)
                                        │
                                        ▼
                   ┌─────────────────────────────────────────┐
                   │ Contextual Sensitivity Classification   │ ◄── DeBERTa / Scikit-Learn (S0–S4)
                   └────────────────────┬────────────────────┘
                                        │
                                        ▼
                   ┌─────────────────────────────────────────┐
                   │       API Purpose Classification        │ ◄── Intent Classifier (8 Purposes)
                   └────────────────────┬────────────────────┘
                                        │
                                        ▼
                   ┌─────────────────────────────────────────┐
                   │ Cumulative Exposure Intelligence Engine │ ◄── R(t) = αS(t) + βC(t) + γL(t) + δD(t)
                   └────────────────────┬────────────────────┘
                                        │
                                        ▼
                   ┌─────────────────────────────────────────┐
                   │    Adaptive Privacy Decision Engine     │ ◄── Base Policy Matrix + Fail-Closed
                   └────────────────────┬────────────────────┘
                                        │
                                        ▼
                   ┌─────────────────────────────────────────┐
                   │  Hybrid Cryptographic Protection Engine │ ◄── HKDF + AES-256-GCM / HMAC / Mask
                   └────────────────────┬────────────────────┘
                                        │
                                        ▼
                   ┌─────────────────────────────────────────┐
                   │ Sanitized Payload / Tokenized Output    │
                   └────────────────────┬────────────────────┘
                                        │
                                        ▼
                   ┌─────────────────────────────────────────┐
                   │ Cryptographically Verifiable Audit Log │ ◄── Forward SHA-256 Hash Chain
                   └─────────────────────────────────────────┘
```

---

## 3. Repository Directory Structure

```text
ebcp_guard/
├── app/
│   ├── api/
│   │   ├── routes/              # REST API endpoints (analyze, protect, decrypt, tokenize, etc.)
│   │   └── schemas/             # Pydantic v2 data models & validation schemas
│   ├── core/                    # Structured logging (automatic PII redaction) & custom exceptions
│   ├── cryptography/            # AES-256-GCM, HMAC-SHA-256, HKDF key manager, masking, audit hash chain
│   ├── database/                # Tortoise ORM models (requests, entities, audit logs, policies)
│   ├── detection/               # Anchored regex detector, Indian banking validators, GLiNER detector
│   ├── evaluation/              # Micro-benchmarks, ablation study suites, and performance metrics
│   ├── exposure/                # Cumulative exposure intelligence & explainable risk scoring
│   ├── nlp/                     # Model loader, sensitivity classifier (S0-S4), purpose classifier
│   ├── policy/                  # Deterministic decision policy matrix & fail-closed engine
│   ├── services/                # Orchestration pipelines (analysis_service, protection_service)
│   ├── static/                  # Professional Web UI (HTML5, Tailwind CSS, Vanilla JS)
│   ├── config.py                # Central Pydantic BaseSettings configuration
│   └── main.py                  # FastAPI application entry point & lifespan manager
├── dataset/
│   ├── synthetic/               # BankPII-API benchmark dataset (requests, logs, multi-request sequences)
│   ├── splits/                  # 70/15/15 Identity-disjoint train/val/test splits
│   └── reports/                 # Dataset compliance and model evaluation reports
├── models/
│   └── checkpoints/             # Trained sensitivity and purpose classifier checkpoints
├── scripts/
│   ├── demo_walkthrough.py      # Guided terminal demonstration script
│   └── init_db.sql              # PostgreSQL schema initialization script
├── simulations/
│   ├── attack_scenarios.py      # 8 controlled red-team security attack scenarios
│   └── red_team_report.py       # Comparative attack benchmark report generator
├── tests/                       # Pytest test suite (29/29 passing)
│   ├── test_api.py              # FastAPI route integration tests
│   ├── test_crypto.py           # Cryptographic primitives & hash chain tests
│   ├── test_detection.py        # Indian banking regex & validator tests
│   ├── test_exposure.py         # Cumulative exposure risk calculation tests
│   ├── test_policy.py           # Policy matrix & fallback tests
│   └── test_security.py         # Security constraints & tamper resistance tests
├── training/                    # Dataset generation, splitting, and model training pipelines
├── .env.example                 # Template environment variables
├── .gitignore                   # Standard repository ignore configuration
├── docker-compose.yml           # Multi-container orchestration (PostgreSQL & Backend)
├── pyproject.toml               # Pytest and project build configuration
├── DEVELOPMENT_STATUS.md        # Comprehensive development status and verification report
├── red_team_report.md           # Red-team adversarial evaluation report
└── README.md                    # System documentation and manuals
```

---

## 4. Quick Start & Setup Guide

### 4.1 Prerequisites
- Python 3.11, 3.12, or 3.13
- Git

### 4.2 Installation

1. **Clone the repository:**
   ```bash
   git clone <YOUR_REPOSITORY_URL>
   cd ebcp_guard
   ```

2. **Create and activate a virtual environment:**
   ```bash
   # Windows PowerShell:
   python -m venv venv
   .\venv\Scripts\Activate.ps1

   # Linux / macOS:
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Initialize environment configuration:**
   ```bash
   # Copy template configuration (defaults to local SQLite and dev cryptographic keys):
   cp .env.example .env
   ```

---

## 5. Running the Application

### 5.1 Start the API Gateway
```bash
# Windows PowerShell:
.\venv\Scripts\uvicorn.exe app.main:app --host 127.0.0.1 --port 8000 --reload

# Linux / macOS:
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### 5.2 Access Interfaces
- **Scroll story with live demos**: Navigate to **`http://127.0.0.1:8000/`** in your browser.
- **Working dashboard**: Navigate to **`http://127.0.0.1:8000/app`**.
- **OpenAPI Interactive Documentation (Swagger UI)**: Navigate to **`http://127.0.0.1:8000/docs`**.
- **Alternative API Reference (ReDoc)**: Navigate to **`http://127.0.0.1:8000/redoc`**.

### 5.3 Prepare the Reveal Demo
Reveal calls the real `/decrypt`, which refuses everyone until service keys exist. For a local demo, add two made-up keys to `.env`, then restart the server:

```bash
python3 -c "
import hashlib, json
h = lambda k: hashlib.sha256(k.encode()).hexdigest()
print('SERVICE_API_KEYS=' + json.dumps({
    'payment_service': {'key_sha256': h('demo-payment-key'), 'tenants': ['demo_bank']},
    'reporting_service': {'key_sha256': h('demo-reporting-key'), 'tenants': ['demo_bank']},
}))" >> .env
```

Then try these in Reveal:

| Key | Result |
|---|---|
| None | 401, refused and audited |
| `demo-reporting-key` | 403, this service may not decrypt |
| `demo-payment-key` | The original value |

Use these keys for local demos only. With no `DATABASE_URL`, the server uses a local SQLite file. A `.env` copied from `.env.example` points at Postgres instead. Run the app with `APP_ENV=development`, because `/protect`, `/analyze` and the log feed require a key outside it.

---

## 6. How to Use the Presentation UI

The built-in web interface is tailored for clean demonstrations and pitching:

1. **Structured Input Form**: Enter customer details (Name, Email, Phone, PAN, Account Number, IFSC) without needing to manually construct JSON.
2. **1-Click Preset Scenarios**:
   - `Core Banking Payment`: Demonstrates **`ENCRYPT`** (AES-256-GCM) for legitimate payment flows.
   - `Analytics & Marketing`: Demonstrates **`ENCRYPT`** (AES-256-GCM) for high-sensitivity identifiers sent to a secondary destination.
   - `Telemetry & Logs`: Demonstrates **`ENCRYPT`** (AES-256-GCM) when high-sensitivity identifiers reach application logging.
   - `Untrusted Third-Party`: Demonstrates **`BLOCK`** (Quarantine containment) when destination is untrusted.
3. **Live JSON Ingress Preview**: Automatically constructs and syntax-highlights the raw payload in real-time.
4. **Execution Pipeline View**: Shows real-time progress across all 7 inspection stages (`Input Normalization`, `Entity Validation`, `Context Classification`, `Purpose Recognition`, `Risk Evaluation`, `Cryptographic Protection`, `Audit Commitment`).
5. **Side-by-Side Payload Comparison**: Displays raw ingress payload side-by-side with the sanitized egress payload.
6. **Adversarial Verification Suite**: Interactive tab allowing judges to execute 8 attack vectors (Dictionary lookup, Cross-tenant correlation, Unauthorized decryption, Audit log tampering, Plaintext log scraping, Slow-leak cumulative profiling, External exfiltration, and Detector evasion).

---

## 7. Verification & Benchmarking

### 7.1 Automated Test Suite
Execute all 29 automated tests across cryptography, detection, risk calculation, policy enforcement, security constraints, and API routes:

```bash
pytest tests/ -v
```

**Results:**
```text
============================= test session starts =============================
collected 29 items

tests/test_api.py .....                                                  [ 17%]
tests/test_crypto.py ........                                            [ 44%]
tests/test_detection.py ...                                              [ 55%]
tests/test_exposure.py ..                                                [ 62%]
tests/test_policy.py ...                                                 [ 72%]
tests/test_security.py ........                                          [100%]

============================= 29 passed in 11.16s =============================
```

### 7.2 Micro-Benchmark Latency
Measure component latency percentiles across 200 iterations:
```bash
python app/evaluation/benchmarks.py
```
- **Regex & Entity Validation**: 0.121 ms (P50: 0.116 ms, P99: 0.208 ms)
- **HMAC-SHA-256 Tokenization**: 0.023 ms (P50: 0.012 ms, P99: 0.022 ms)
- **AES-256-GCM Encryption**: 0.018 ms (P50: 0.016 ms, P99: 0.027 ms)
- **Cumulative Exposure Scoring**: 0.009 ms (P50: 0.008 ms, P99: 0.017 ms)
- **Policy Decision Engine**: 0.044 ms (P50: 0.042 ms, P99: 0.072 ms)
- **Total Pipeline Overhead**: **< 0.35 ms** at P99.

### 7.3 Guided Terminal Demonstration
Run the 5-Act interactive presentation script:
```bash
python scripts/demo_walkthrough.py
```

### 7.4 Red-Team Attack Report Generator
Generate the comparative baseline vs. EBCP-Guard security evaluation table:
```bash
python -m simulations.red_team_report
```

---

## 8. Core Technical Formulations

### 8.1 Cumulative Exposure Risk Formula
The total risk $R(t)$ at timestamp $t$ is calculated as:

$$R(t) = \alpha S(t) + \beta C(t) + \gamma L(t) + \delta D(t)$$

| Symbol | Weight | Range | Definition |
|---|---|---|---|
| **$S(t)$** | $\alpha = 0.35$ | $0.0 - 1.0$ | Payload sensitivity score from classes S0 (0.0) through S4 (1.0). |
| **$C(t)$** | $\beta = 0.30$ | $0.0 - 1.0$ | Historical cumulative exposure with logistic saturation: $C(t) = 1 - e^{-\lambda \sum w_i}$. |
| **$L(t)$** | $\gamma = 0.20$ | $0.0 - 1.0$ | Graph linkability score linking customer identifiers to external entities. |
| **$D(t)$** | $\delta = 0.15$ | $0.0 - 1.0$ | Destination untrust score (Core Banking = 0.0, Blacklisted Partner = 1.0). |

### 8.2 Key Derivation Hierarchy (HKDF-SHA-256)
Keys are derived on-demand with strict domain separation:
```
Master Key (256-bit Hardware Key Storage)
   │
   ├── HKDF-Expand(MasterKey, "tenant:{tenant_id}") ───────► Tenant Key
   │                                                             │
   │                                                             ├── HKDF-Expand(TenantKey, "purpose:{purpose}") ──► Purpose Key
   │                                                             │                                                        │
   │                                                             │                                                        └── HKDF-Expand(PurposeKey, "epoch:{epoch_id}") ──► HMAC Token Key
   │                                                             └── HKDF-Expand(TenantKey, "aes_encryption") ────► AES-256-GCM Key
   └── HKDF-Expand(MasterKey, "audit_integrity") ──────────► Audit Trail Hash Key
```

### 8.3 Cryptographic Audit Hash Chain
Audit records form an immutable forward-linked SHA-256 hash chain:

$$H_i = \text{SHA-256}(H_{i-1} \parallel \text{canonical\_metadata}_i)$$

Any retro-active alteration of historical records invalidates all subsequent hashes, providing mathematical proof of tampering.

---

## 9. API Reference

### 9.1 Inspect Payload (`POST /api/v1/analyze`)
Evaluates sensitivity, purpose, and cumulative exposure without altering the payload.

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/analyze" \
     -H "Content-Type: application/json" \
     -d '{
       "payload": {
         "customer_name": "Rohan Gupta",
         "email": "rohan.gupta@example.in",
         "pan": "ABCPE1234F",
         "account_number": "123456789012"
       },
       "endpoint": "/api/v1/payments",
       "http_method": "POST",
       "destination_service": "internal_payment",
       "tenant_id": "bank_alpha"
     }'
```

### 9.2 Intercept & Protect Payload (`POST /api/v1/protect`)
Applies cryptographic transformations (AES-256-GCM encryption, HMAC tokenization, or masking) and commits an audit record.

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/protect" \
     -H "Content-Type: application/json" \
     -d '{
       "payload": {
         "name": "Priya Sharma",
         "email": "priya.sharma@example.com",
         "pan": "ABCPS1234F"
       },
       "endpoint": "/api/v1/customer/profile",
       "destination_service": "marketing_crm",
       "tenant_id": "bank_alpha"
     }'
```

### 9.3 Decrypt Ciphertext (`POST /api/v1/decrypt`)
Reverses AES-256-GCM ciphertexts for authorized service roles.

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/decrypt" \
     -H "Content-Type: application/json" \
     -d '{
       "ciphertext_entries": [
         {
           "key": "account_number",
           "ciphertext_b64": "<CIPHERTEXT_PACKAGE>",
           "entity_type": "ACCOUNT_NUMBER"
         }
       ],
       "calling_service": "payment_service",
       "tenant_id": "bank_alpha",
       "purpose": "PAYMENT_PROCESSING"
     }'
```

### 9.4 Execute Attack Simulation (`POST /api/v1/simulate-attack`)
Demonstrates security resistance against any of the 8 controlled adversarial scenarios (`dict_attack`, `cross_tenant`, `unauth_decrypt`, `audit_tamper`, `plaintext_log`, `cumulative`, `exfiltration`, `evasion`).

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/simulate-attack" \
     -H "Content-Type: application/json" \
     -d '{
       "scenario": "dict_attack",
       "tenant_id": "demo_bank"
     }'
```

---

## 10. Git Setup & Push Instructions

When you create your remote repository (e.g. on GitHub or GitLab), push the codebase using:

```bash
# 1. Add all project files:
git add .

# 2. Create the initial commit:
git commit -m "feat: complete EBCP-Guard framework with AI classification, hybrid cryptography, and web UI"

# 3. Link your remote repository:
git remote add origin <YOUR_REMOTE_REPOSITORY_URL>

# 4. Set the main branch and push:
git branch -M main
git push -u origin main
```

---

## 11. Security & Compliance Statement

- **Non-Functional Synthetic Data**: All customer identities, PANs, Aadhaar numbers, accounts, and transaction records used in testing, demonstration, and training are synthetically generated and non-functional.
- **Zero Raw PII Persistence**: EBCP-Guard guarantees that raw, unencrypted PII never touches persistent storage, audit logs, or error traces.
- **Regulatory Alignment**: Designed in compliance with RBI Master Directions on IT Governance & Cybersecurity, DPDP Act 2023, and GDPR Article 32.
