# 01 - SOC Detection & Response Platform

A minimal, safe, local SOC detection and response platform in pure Python (standard library only). It ingests demo security events, runs detection rules mapped to MITRE ATT&CK, scores and triages alerts, and writes a response playbook recommendation for each alert.

No live data, no real attacks, no network calls. All events in `demo_data/` are synthetic and clearly labelled as demo data.

## What it does

- Normalises demo events (auth, process, network, file) into one schema
- Runs 5 detection rules, each mapped to MITRE ATT&CK tactics and techniques
- Scores severity, deduplicates repeat alerts, and assigns a triage status
- Recommends a response action per rule (isolate host, reset credentials, block IP, investigate)
- Writes `out/alerts.json` and prints a SOC summary to the terminal

## MITRE ATT&CK mapping

| Rule | Tactic | Technique | What it detects |
|---|---|---|---|
| brute-force-login | Credential Access | T1110.001 Password Guessing | 5+ failed logins from one IP in 10 minutes |
| encoded-powershell | Execution | T1059.001 PowerShell | PowerShell with `-EncodedCommand` |
| lateral-movement-smb | Lateral Movement | T1021.002 SMB/Windows Admin Shares | SMB to admin share from a non-admin host |
| suspicious-outbound | Command and Control | T1071.001 Web Protocols | Outbound to a known-bad demo domain / rare port |
| mass-file-rename | Impact | T1486 Data Encrypted for Impact | 10+ file renames in 1 minute on one host |

## How to run

```bash
cd 01-soc-detection-response-platform
python3 src/soc_platform.py --events demo_data/events.json --out out/alerts.json
```

Expected output: 5 alerts (one per rule), severity High for brute force and mass rename, Medium for the rest. No dependencies to install.

## Files

- `src/soc_platform.py` - detection engine, rules, scoring, triage
- `src/rules.json` - detection rules with ATT&CK mapping, editable without touching code
- `demo_data/events.json` - 24 synthetic events that trigger every rule
- `docs/architecture.md` - architecture, data flow, and how to extend it
- `requirements.txt` - standard library only, nothing to install

## What an employer sees

A working detection pipeline, not a slide deck: rules as data, ATT&CK mapping, alert triage, and a clear path from event to response. The next step is adding a new rule in `src/rules.json` and a matching demo event.
