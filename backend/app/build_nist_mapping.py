"""Create a simple mapping from PWNDORA lab categories to NIST CSF functions.

This script writes `nist_csf_mapping.json` to `backend/app/data/` with the
following structure:
  { "Network Scanning": "Identify", ... }

It also prints a one-line justification for each mapping to the console so
you can copy those lines into `ARCHITECTURE.md`.
"""

from __future__ import annotations

import json
import os
from typing import Dict


CATEGORIES = [
    "Network Scanning",
    "Phishing Simulation",
    "Password Attacks",
    "Privilege Escalation",
    "Lateral Movement",
    "Web Application Exploitation",
    "Persistence",
    "Defense Evasion",
    "Command and Control / Exfiltration",
    "Discovery",
]


# Realistic mapping from lab category to one NIST CSF function.
# Reasoning is intentionally concise and printed below for easy copy/paste.
NIST_MAP: Dict[str, str] = {
    "Network Scanning": "Identify",
    "Phishing Simulation": "Detect",
    "Password Attacks": "Protect",
    "Privilege Escalation": "Protect",
    "Lateral Movement": "Detect",
    "Web Application Exploitation": "Protect",
    "Persistence": "Respond",
    "Defense Evasion": "Detect",
    "Command and Control / Exfiltration": "Respond",
    "Discovery": "Identify",
}


JUSTIFICATIONS: Dict[str, str] = {
    "Network Scanning": (
        "Identify inventory and external exposure: scanning/discovery labs help map assets, "
        "which supports Asset Management and risk identification (Identify)."
    ),
    "Phishing Simulation": (
        "Simulations exercise detection capabilities and user-reporting processes; "
        "they validate telemetry and controls used to detect phishing (Detect)."
    ),
    "Password Attacks": (
        "Hardening credentials and access controls prevents compromise; defenses like MFA "
        "and password policies are protective controls (Protect)."
    ),
    "Privilege Escalation": (
        "Mitigations (least privilege, patching) are protective controls to limit escalation; "
        "thus these labs align with Protect."
    ),
    "Lateral Movement": (
        "Detection of lateral movement (monitoring, EDR) is key to identifying ongoing breaches; "
        "labs focus on Detect practices."
    ),
    "Web Application Exploitation": (
        "Preventive controls (secure coding, WAFs, input validation) reduce web exploitation risk; "
        "therefore Protect is appropriate."
    ),
    "Persistence": (
        "Exercises for removing persistent footholds and playbooks map to response actions; "
        "these labs support Respond."
    ),
    "Defense Evasion": (
        "Detecting evasion techniques (logging, anomaly detection) allows defenders to find stealthy activity; "
        "Detect is the best fit."
    ),
    "Command and Control / Exfiltration": (
        "Containment and eradication of C2 and exfiltration are core response activities; "
        "labs exercising those behaviors map to Respond."
    ),
    "Discovery": (
        "Discovery/scanning labs build understanding of environment and attack surface, supporting risk and asset identification (Identify)."
    ),
}


def write_mapping(out_path: str) -> None:
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(NIST_MAP, f, indent=2, sort_keys=True)


def main() -> None:
    here = os.path.dirname(__file__)
    out_path = os.path.abspath(os.path.join(here, "data", "nist_csf_mapping.json"))

    # Validate that all required categories are present in the mapping
    missing = [c for c in CATEGORIES if c not in NIST_MAP]
    if missing:
        raise RuntimeError(f"Missing mappings for categories: {missing}")

    write_mapping(out_path)

    # Print one-line justifications for ARCHITECTURE.md
    for cat in CATEGORIES:
        func = NIST_MAP[cat]
        justification = JUSTIFICATIONS.get(cat, "")
        print(f"{cat}: {func} — {justification}")

    print(f"Wrote NIST CSF mapping to {out_path}")


if __name__ == "__main__":
    main()
