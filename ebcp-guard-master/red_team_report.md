# EBCP-Guard Red-Team Attack Simulation & Security Evaluation Report
*Generated: 2026-11-04T21:27:28.226479+00:00*

| Attack | Objective | Baseline Outcome | EBCP-Guard Outcome | Result |
|---|---|---|---|---|
| **Plaintext log extraction** | Recover customer PII from standard application logs | PII EXPOSED: attacker recovered: name='Arjun Mehta', email='arjun.mehta@example.... | PII PROTECTED: attacker sees: '[INFO] Payment initiated by A. M. (email: a******... | **PROTECTED** |
| **Plain hash dictionary attack** | Match precomputed hashes of common emails against tokens | SHA256 MATCHED — target email found in dictionary. Hash: 6cd1cf87520cfbc7...... | HMAC RESISTED — attacker without key produced: EMAIL_1a8e83464593e5585834b17fba.... | **PROTECTED** |
| **Cross-context token correlation** | Correlate customer tokens across distinct business scopes | With reusable identifiers (customer_id/email), cross-scope correlation is trivia... | Tokens are scope-separated: same_scope_stable=True, cross_purpose_separated=True... | **PROTECTED** |
| **Cumulative information disclosure** | Aggregate multi-request low-sensitivity disclosures to reconstruct identity | Per-request decisions: ['ALLOW', 'MASK', 'MASK', 'MASK'] — each request appears ... | Cumulative decision: TOKENIZE — risk escalation detected: True... | **PROTECTED** |
| **Unauthorized decryption** | Attempt AES-256-GCM decryption without credentials or with altered ciphertext | Without access controls, any party with the ciphertext could attempt decryption.... | Unauthorized attempts blocked via GCM authentication tag. Authorized party succe... | **PROTECTED** |
| **Audit log tampering** | Modify past audit event and test whether hash-chain/Merkle verification detects it | Without hash chaining, event modification may go undetected.... | Original chain: valid=True. After tampering: valid=False, first failure at seq=3... | **PROTECTED** |
| **External data exfiltration policy** | Exfiltrate sensitive financial records to unapproved external endpoints | Static rules only check destination whitelist; miss contextual PII sensitivity.... | Decision: BLOCK, blocked=True, reason='Destination 'external_unknown' is not aut... | **PROTECTED** |
| **Model evasion and uncertainty** | Probe detector with obfuscated and misspelled sensitive identifiers | Simple regex with exact patterns fails on obfuscated input.... | Hybrid detector found matches in 4/5 obfuscated samples. Missed 1 — conservative... | **PARTIAL** |

## Technical Explanations

### Plaintext log extraction (`plaintext_log`)
- **Security Result**: `PROTECTED`
- **Baseline Risk**: PII EXPOSED: attacker recovered: name='Arjun Mehta', email='arjun.mehta@example.com', account='112345678901'
- **EBCP-Guard Defense**: PII PROTECTED: attacker sees: '[INFO] Payment initiated by A. M. (email: a*********a@example.com) from account ********8901 amount INR 15000'
- **Mechanism**: Baseline logs expose customer name, email, and account number in plaintext. An attacker with log access can immediately identify and target the customer. EBCP-Guard replaces sensitive values with masked equivalents before logging, preventing direct PII extraction from log files.

### Plain hash dictionary attack (`dict_attack`)
- **Security Result**: `PROTECTED`
- **Baseline Risk**: SHA256 MATCHED — target email found in dictionary. Hash: 6cd1cf87520cfbc7...
- **EBCP-Guard Defense**: HMAC RESISTED — attacker without key produced: EMAIL_1a8e83464593e5585834b17fba... (no match)
- **Mechanism**: Plain SHA256(email) is deterministic — an attacker with a list of likely emails can pre-compute hashes and match them against stored tokens (dictionary attack). HMAC-SHA256 with a secret key prevents this: without the key, no matching is possible. Security depends on keeping the HMAC key secret and using secure key management.

### Cross-context token correlation (`cross_tenant`)
- **Security Result**: `PROTECTED`
- **Baseline Risk**: With reusable identifiers (customer_id/email), cross-scope correlation is trivial.
- **EBCP-Guard Defense**: Tokens are scope-separated: same_scope_stable=True, cross_purpose_separated=True, cross_tenant_separated=True
- **Mechanism**: Purpose-bound pseudonymization ensures the same customer email produces DIFFERENT tokens in different authorized scopes. An attacker who obtains analytics tokens cannot directly link them to payment tokens for the same customer. Within the same authorized scope, tokens are stable to enable legitimate correlation.

### Cumulative information disclosure (`cumulative`)
- **Security Result**: `PROTECTED`
- **Baseline Risk**: Per-request decisions: ['ALLOW', 'MASK', 'MASK', 'MASK'] — each request appears acceptable individually.
- **EBCP-Guard Defense**: Cumulative decision: TOKENIZE — risk escalation detected: True
- **Mechanism**: Conventional DLP checks each API request independently. Four individually low-risk disclosures (amount, location, partial account, email) collectively enable customer profiling and unauthorized correlation. EBCP-Guard's cumulative exposure engine tracks historical disclosures and escalates the protection decision when aggregate risk exceeds thresholds.

### Unauthorized decryption (`unauth_decrypt`)
- **Security Result**: `PROTECTED`
- **Baseline Risk**: Without access controls, any party with the ciphertext could attempt decryption.
- **EBCP-Guard Defense**: Unauthorized attempts blocked via GCM authentication tag. Authorized party succeeds.
- **Mechanism**: AES-256-GCM provides authenticated encryption: any modification to ciphertext, nonce, or use of the wrong key causes immediate authentication tag verification failure. An attacker who intercepts the ciphertext cannot decrypt it without the correct purpose-scoped derived key. Authorized services with the correct scope succeed.

### Audit log tampering (`audit_tamper`)
- **Security Result**: `PROTECTED`
- **Baseline Risk**: Without hash chaining, event modification may go undetected.
- **EBCP-Guard Defense**: Original chain: valid=True. After tampering: valid=False, first failure at seq=3
- **Mechanism**: The SHA-256 hash chain makes tampering detectable: modifying event N changes its hash, which cascades forward and breaks the chain at event N+1. NOTE: Hash chains are tamper-EVIDENT, not tamper-PROOF. For stronger guarantees, Merkle roots should be stored in an independent, trusted external checkpoint.

### External data exfiltration policy (`exfiltration`)
- **Security Result**: `PROTECTED`
- **Baseline Risk**: Static rules only check destination whitelist; miss contextual PII sensitivity.
- **EBCP-Guard Defense**: Decision: BLOCK, blocked=True, reason='Destination 'external_unknown' is not authorized.'
- **Mechanism**: The policy engine checks the destination against the authorized service registry, cross-references with entity sensitivity and processing purpose, and blocks the request when the destination is not authorized to receive the identified sensitive entities.

### Model evasion and uncertainty (`evasion`)
- **Security Result**: `PARTIAL`
- **Baseline Risk**: Simple regex with exact patterns fails on obfuscated input.
- **EBCP-Guard Defense**: Hybrid detector found matches in 4/5 obfuscated samples. Missed 1 — conservative policy applied for low-confidence predictions.
- **Mechanism**: Model evasion is a real limitation — no detection system achieves 100% recall. EBCP-Guard mitigates this through: (1) hybrid detection combining GLiNER + regex, (2) conservative handling for low-confidence predictions, (3) fail-closed policy: unclassified sensitive content defaults to TOKENIZE or ENCRYPT. Perfect protection is not claimed — these failure modes are documented.
