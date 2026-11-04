"""
EBCP-Guard Automated Red Team Report Generator
================================================
Executes all eight security attack demonstrations against local synthetic data
and outputs an executive Markdown table and full audit summary.
"""

from __future__ import annotations

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import asyncio
import json
from datetime import datetime, timezone
from app.api.schemas.schemas import AttackSimulationRequest
from simulations.attack_scenarios import (
    run_attack_scenario,
    attack_1_plaintext_log,
    attack_2_dict_attack,
    attack_3_cross_tenant,
    attack_4_cumulative_exposure,
    attack_5_unauth_decrypt,
    attack_6_audit_tamper,
    attack_7_exfiltration,
    attack_8_model_evasion,
)

SCENARIOS = [
    ("plaintext_log", "Plaintext log extraction", "Recover customer PII from standard application logs"),
    ("dict_attack", "Plain hash dictionary attack", "Match precomputed hashes of common emails against tokens"),
    ("cross_tenant", "Cross-context token correlation", "Correlate customer tokens across distinct business scopes"),
    ("cumulative", "Cumulative information disclosure", "Aggregate multi-request low-sensitivity disclosures to reconstruct identity"),
    ("unauth_decrypt", "Unauthorized decryption", "Attempt AES-256-GCM decryption without credentials or with altered ciphertext"),
    ("audit_tamper", "Audit log tampering", "Modify past audit event and test whether hash-chain/Merkle verification detects it"),
    ("exfiltration", "External data exfiltration policy", "Exfiltrate sensitive financial records to unapproved external endpoints"),
    ("evasion", "Model evasion and uncertainty", "Probe detector with obfuscated and misspelled sensitive identifiers"),
]

def generate_red_team_report() -> dict:
    """Run all attack simulations and compile structured results."""
    report_items = []

    print("\n" + "=" * 70, flush=True)
    print("EBCP-GUARD RED-TEAM SECURITY DEMONSTRATION SUITE", flush=True)
    print("=" * 70, flush=True)

    handlers = {
        "plaintext_log": attack_1_plaintext_log,
        "dict_attack": attack_2_dict_attack,
        "cross_tenant": attack_3_cross_tenant,
        "cumulative": attack_4_cumulative_exposure,
        "unauth_decrypt": attack_5_unauth_decrypt,
        "audit_tamper": attack_6_audit_tamper,
        "exfiltration": attack_7_exfiltration,
        "evasion": attack_8_model_evasion,
    }

    for scenario_id, title, objective in SCENARIOS:
        req = AttackSimulationRequest(scenario=scenario_id, tenant_id="bank_demo")
        handler = handlers.get(scenario_id)
        resp = handler(req)

        report_items.append({
            "scenario_id": scenario_id,
            "title": title,
            "objective": objective,
            "baseline_outcome": resp.baseline_outcome,
            "ebcp_guard_outcome": resp.ebcp_guard_outcome,
            "result": resp.result,
            "explanation": resp.explanation,
            "details": resp.details,
        })
        print(f"[*] {title.ljust(38)}: {resp.result}", flush=True)

    print("=" * 70 + "\n", flush=True)
    return {
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "total_scenarios": len(SCENARIOS),
        "results": report_items,
    }

def format_markdown_table(report: dict) -> str:
    """Format report into GitHub-flavored Markdown table as requested in specification."""
    lines = [
        "# EBCP-Guard Red-Team Attack Simulation & Security Evaluation Report",
        f"*Generated: {report['timestamp']}*\n",
        "| Attack | Objective | Baseline Outcome | EBCP-Guard Outcome | Result |",
        "|---|---|---|---|---|",
    ]

    for item in report["results"]:
        lines.append(
            f"| **{item['title']}** | {item['objective']} | {item['baseline_outcome'][:80]}... | {item['ebcp_guard_outcome'][:80]}... | **{item['result']}** |"
        )

    lines.append("\n## Technical Explanations\n")
    for item in report["results"]:
        lines.append(f"### {item['title']} (`{item['scenario_id']}`)")
        lines.append(f"- **Security Result**: `{item['result']}`")
        lines.append(f"- **Baseline Risk**: {item['baseline_outcome']}")
        lines.append(f"- **EBCP-Guard Defense**: {item['ebcp_guard_outcome']}")
        lines.append(f"- **Mechanism**: {item['explanation']}\n")

    return "\n".join(lines)

if __name__ == "__main__":
    report = generate_red_team_report()
    md = format_markdown_table(report)
    with open("red_team_report.md", "w", encoding="utf-8") as f:
        f.write(md)
    print("Report saved to red_team_report.md", flush=True)
