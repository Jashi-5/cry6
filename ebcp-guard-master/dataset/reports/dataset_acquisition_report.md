# EBCP-Guard Dataset Acquisition & Compliance Report

## Executive Summary
This document provides legal verification, schema analysis, and integration plans for all public and synthetic datasets integrated into EBCP-Guard.

---

## 1. Public Datasets Audit

### Dataset A: AI4Privacy OpenPII
- **Source**: `https://huggingface.co/datasets/ai4privacy/pii-masking-openpii-1m`
- **License**: Apache-2.0 (Permissive; Commercial and Academic use authorized)
- **Size**: ~1.4M multilingual synthetic records
- **Features**: `text`, `privacy_mask`, `unmasked_text`, `spans`
- **Label Schema**: BIO and span-level personal identifiers (NAME, EMAIL, PHONE, ADDRESS, etc.)
- **Usage**: General PII detection benchmark and cross-evaluation against GLiNER and Presidio.
- **Preprocessing Requirements**: Convert span character offsets to standard `(start, end, entity_type)` tuples. Filter for English (`en`) subset for banking compatibility.
- **Limitations**: Synthetic generation patterns may lack bank-specific context (e.g. IFSC, UPI).

### Dataset B: AI4Privacy PFI Masking
- **Source**: `https://huggingface.co/datasets/ai4privacy/pfi-masking-100k-full`
- **License**: **Restricted / Custom Research License**
- **Audit Finding**: Distribution license prohibits unapproved redistribution and commercial weights derivative.
- **Resolution**: **EXCLUDED FROM MODEL WEIGHT DISTRIBUTION**. Replaced with custom Indian banking synthetic samples in `BankPII-API` to guarantee 100% clean IP and unencumbered research replication.

### Dataset C: SFinDSet (Synthetic Financial Dataset)
- **Source**: `https://www.kaggle.com/dsv/11299085`
- **License**: CC-BY-4.0 (Attribution required; commercial and research authorized)
- **Size**: Structured transaction sequences
- **Features**: `account_id`, `transaction_amount`, `merchant_category`, `timestamp`
- **Usage**: Multi-request cumulative exposure timeline modeling and graph linkability verification.
- **Preprocessing**: Map tabular schemas into realistic REST API payloads (`/api/v1/payments/transfer`).

### Dataset D: Synthetic PII Financial Documents
- **Source**: `https://data.mendeley.com/datasets/tzrjx692jy/1`
- **License**: CC-BY-4.0
- **Size**: Unstructured financial statements and invoice text
- **Usage**: Unstructured log extraction validation and complex financial text NER.

---

## 2. Proprietary Benchmark: BankPII-API

- **Name**: BankPII-API: Synthetic Banking API Privacy and Exposure Benchmark
- **Generation Method**: Deterministic algorithmic generator (`generate_bankpii_dataset.py`) using Faker (Indian locale) and regulatory banking templates.
- **Target Volume**: 195,000 total (Initial prototype generation: 6,500 active records).
- **Domain Specialization**:
  - Permanent Account Number (PAN): `[A-Z]{5}[0-9]{4}[A-Z]`
  - Indian Financial System Code (IFSC): `[A-Z]{4}0[A-Z0-9]{6}`
  - Unified Payments Interface (UPI Virtual Address): `user@provider`
  - Aadhaar Format Identifiers: 12-digit spaced blocks
  - Core Banking Account Numbers: 11–16 digits
  - API Routes: 10 representative financial microservice endpoints
  - Multi-request Progressive Exposure Sequences: 4-stage disclosure sequences

---

## 3. Dataset Splitting Strategy
- **70% Training / 15% Validation / 15% Test**
- **Identity Disjointness**: Customer identifiers (`synthetic_customer_id`) never cross split boundaries.
- **Temporal Integrity**: Complete multi-request disclosure sequences are strictly kept within a single split to avoid temporal data leakage.
