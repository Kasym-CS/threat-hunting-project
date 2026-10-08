# Spear-Phishing as an Initial Access Vector: Hunting Malicious PowerShell Execution

**Course:** Introduction to Threat Hunting — Astana IT University, 2026–2027
**Author:** <Your Name>, group <Group>
**Format:** individual (solo) project, weekly increments defended in practice sessions

## Project Overview

Spear-phishing remains one of the most common ways attackers gain initial access to an organization. A typical chain looks like this:

```
Phishing email → malicious attachment/link → user opens it → Office/script host spawns PowerShell
→ PowerShell downloads a payload → persistence → command and control → data exfiltration
```

This project follows that chain through the whole course: from collecting threat intelligence about phishing campaigns (weeks 1–3), through modelling the attack with the Cyber Kill Chain and MITRE ATT&CK (weeks 4, 6), to building and testing hunting hypotheses for malicious PowerShell execution in a SIEM (weeks 5, 7–9), and finally comparing the results with the TTPs of APT29, a group well known for spear-phishing operations (week 10).

## Key ATT&CK Techniques in Scope

| ID | Technique | Role in the chain |
|---|---|---|
| T1566.001 | Phishing: Spearphishing Attachment | Initial access |
| T1566.002 | Phishing: Spearphishing Link | Initial access |
| T1204.002 | User Execution: Malicious File | Execution trigger |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Execution |
| T1027 | Obfuscated Files or Information | Defense evasion |
| T1105 | Ingress Tool Transfer | Payload download |

## Weekly Progress

| Week | Topic | Deliverables | Status |
|---|---|---|---|
| 1 | Cyber Threat Intelligence Fundamentals | [Glossary](week-01/glossary.md), [Threat classification](week-01/threat-classification.md) | ✅ |
| 2 | Data Collection Process | [OSINT report](week-02/osint-report.md), [Data source mapping](week-02/data-source-mapping.md) | ✅ |
| 3 | Data Processing and Exploitation | [MISP deployment](week-03/misp-deployment.md), [Normalization](week-03/normalization.md), [Script](week-03/scripts/normalize_iocs.py), [Clean IOC report](week-03/ioc-report.md) | ✅ |
| 4 | The Cyber Kill Chain | [Kill Chain analysis of APT29 phishing (2018)](week-04/kill-chain-analysis.md), [ATT&CK Navigator layer](week-04/apt29-2018-navigator-layer.json) | ✅ |
| 5 | Threat Hunting Concept | — | ⏳ |
| 6 | ATT&CK Framework | — | ⏳ |
| 7 | MITRE CAR | — | ⏳ |
| 8 | Adversary Emulation Plan | — | ⏳ |
| 9 | Atomic Red Team | — | ⏳ |
| 10 | APT Techniques (APT29) | — | ⏳ |

## Tools

Shodan, VirusTotal, Maltego CE, MISP (Docker), Python 3; later: Sysmon, Elastic Stack / Splunk, Atomic Red Team.

## Ethics and Scope

All data collection is passive and uses public sources only. No scanning, probing or interaction with third-party systems is performed. Phishing URLs are never opened in a browser and are stored defanged. Attack simulations (weeks 8–9) run only in an isolated virtual lab.
