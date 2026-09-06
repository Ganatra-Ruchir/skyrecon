"""A trimmed ATT&CK lookup so alerts speak the language SOCs report in."""

from __future__ import annotations

TECHNIQUES: dict[str, dict[str, str]] = {
    "T1027":     {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
    "T1030":     {"name": "Data Transfer Size Limits", "tactic": "Exfiltration"},
    "T1041":     {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    "T1059.001": {"name": "PowerShell", "tactic": "Execution"},
    "T1068":     {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
    "T1071.001": {"name": "Web Protocols", "tactic": "Command and Control"},
    "T1105":     {"name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "T1110":     {"name": "Brute Force", "tactic": "Credential Access"},
    "T1189":     {"name": "Drive-by Compromise", "tactic": "Initial Access"},
    "T1204.002": {"name": "Malicious File", "tactic": "Execution"},
    "T1486":     {"name": "Data Encrypted for Impact", "tactic": "Impact"},
    "T1490":     {"name": "Inhibit System Recovery", "tactic": "Impact"},
    "T1547":     {"name": "Boot or Logon Autostart Execution", "tactic": "Persistence"},
    "T1566.001": {"name": "Spearphishing Attachment", "tactic": "Initial Access"},
    "T1566.002": {"name": "Spearphishing Link", "tactic": "Initial Access"},
    "T1568.002": {"name": "Domain Generation Algorithms", "tactic": "Command and Control"},
    "T1573":     {"name": "Encrypted Channel", "tactic": "Command and Control"},
    "T1595":     {"name": "Active Scanning", "tactic": "Reconnaissance"},
}

KILL_CHAIN_ORDER = [
    "Reconnaissance", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Command and Control", "Exfiltration", "Impact",
]


def describe(ids: str | list[str]) -> list[dict]:
    raw = ids.split(",") if isinstance(ids, str) else list(ids)
    out = []
    for tid in [t.strip().upper() for t in raw if t and t.strip()]:
        meta = TECHNIQUES.get(tid, {"name": "Unmapped technique", "tactic": "Unknown"})
        out.append({"id": tid, "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/", **meta})
    return out


def coverage(technique_ids: list[str]) -> dict[str, int]:
    """How many alerts land in each kill-chain stage — a SOC coverage view."""
    tally = dict.fromkeys(KILL_CHAIN_ORDER, 0)
    for tid in technique_ids:
        meta = TECHNIQUES.get(tid.strip().upper())
        if meta and meta["tactic"] in tally:
            tally[meta["tactic"]] += 1
    return tally
