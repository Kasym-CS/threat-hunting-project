# Week 1 — CTI Glossary

Key Cyber Threat Intelligence terms, each illustrated with an example from the project topic (spear-phishing leading to malicious PowerShell execution).

## Core CTI Concepts

| Term | Definition | Example in this project |
|---|---|---|
| Cyber Threat Intelligence (CTI) | Evidence-based knowledge about threats, their actors and methods, collected and analysed to support security decisions. | Collecting data on active phishing domains to block them before employees receive the emails. |
| Intelligence Lifecycle | The cycle of Direction → Collection → Processing → Analysis → Dissemination → Feedback that turns raw data into intelligence. | Weeks 1–3 of this project follow the first three stages: defining the topic, OSINT collection, MISP processing. |
| Indicator of Compromise (IOC) | An observable artefact suggesting a system was compromised: hash, IP, domain, URL, email address. | A phishing domain `secure-kaspi-login[.]com` or the SHA-256 of a malicious `.docm` attachment. |
| Indicator of Attack (IOA) | Behaviour that shows an attack is in progress, independent of specific artefacts. | `WINWORD.EXE` spawning `powershell.exe` with an encoded command. |
| TTP (Tactics, Techniques, Procedures) | How an adversary operates: the goal (tactic), the method (technique) and the specific implementation (procedure). | Tactic: Execution; Technique: T1059.001 PowerShell; Procedure: `powershell -enc <base64>` launched from a macro. |
| Threat Actor | An individual or group conducting malicious activity. | APT29, or a financially motivated group running credential-phishing kits. |
| Advanced Persistent Threat (APT) | A well-resourced, usually state-sponsored actor conducting long-term targeted operations. | APT29 (G0016), known for spear-phishing government and diplomatic targets. |
| Campaign | A set of related intrusion activities by the same actor over a period of time, with shared goals and infrastructure. | A wave of emails impersonating a bank, all linking to domains on the same hosting provider. |
| Threat Landscape | The overall picture of current threats relevant to a sector, region or organization. | ENISA Threat Landscape lists social engineering among the prime threats in the EU. |
| Attack Surface | All points where an attacker can try to enter or extract data from a system. | Corporate email inboxes and users who can open Office macros. |

## Levels of Intelligence

| Term | Definition | Example in this project |
|---|---|---|
| Strategic Intelligence | High-level, non-technical analysis of trends and risks for management. | "Phishing remains the leading initial access vector; investment in email security and awareness is justified." |
| Operational Intelligence | Information about specific campaigns, their timing, targets and intent. | "A campaign impersonating eGov notifications is targeting Kazakhstan users this month." |
| Tactical Intelligence | Information about adversary TTPs used by defenders to build detections. | "The group uses macros that launch obfuscated PowerShell to download a loader." |
| Technical Intelligence | Low-level, machine-readable indicators with a short lifetime. | A list of 50 phishing URLs and C2 IPs imported into MISP. |

## Models and Frameworks

| Term | Definition | Example in this project |
|---|---|---|
| Cyber Kill Chain | Lockheed Martin model of 7 attack stages: Reconnaissance, Weaponization, Delivery, Exploitation, Installation, C2, Actions on Objectives. | Delivery = the phishing email; Exploitation = the user enabling macros. |
| MITRE ATT&CK | A public knowledge base of adversary tactics and techniques based on real-world observations. | Mapping the attack chain to T1566.001, T1204.002 and T1059.001. |
| Diamond Model | Describes an intrusion through four linked features: Adversary, Capability, Infrastructure, Victim. | Adversary: phishing group; Capability: macro dropper; Infrastructure: phishing domain; Victim: bank customers. |
| Pyramid of Pain | Shows how much effort it costs an attacker when defenders detect each indicator type, from hashes (easy to change) up to TTPs (hard to change). | Blocking a domain is trivial for the attacker to bypass; detecting "Office spawns PowerShell" forces them to change technique. |
| MITRE CAR | Cyber Analytics Repository: detection analytics mapped to ATT&CK techniques. | Will be used in week 7 to implement a PowerShell execution analytic. |

## Sharing and Handling

| Term | Definition | Example in this project |
|---|---|---|
| TLP (Traffic Light Protocol) | Labels that define how widely information may be shared: CLEAR, GREEN, AMBER, RED. | IOCs in MISP are tagged `tlp:green` — shareable within the community. |
| STIX | Structured Threat Information Expression: a standard JSON format for describing threat intelligence. | MISP events can be exported as STIX 2.1. |
| TAXII | Trusted Automated Exchange of Intelligence Information: a protocol for transporting STIX data. | A TAXII feed could deliver phishing IOCs automatically. |
| MISP | Open-source Threat Intelligence Platform for storing, correlating and sharing IOCs. | Deployed in week 3 to store and correlate collected phishing IOCs. |
| Defanging | Modifying an IOC so it cannot be clicked or executed accidentally. | `http://evil.com` → `hxxp://evil[.]com` |
| False Positive | An alert or indicator that looks malicious but is benign. | `google.com` appearing in a phishing IOC list because the page loaded Google fonts. |

## Topic-Specific Terms

| Term | Definition | Example in this project |
|---|---|---|
| Phishing | Fraudulent messages that trick users into revealing data or running malicious code. | Mass email "Your account is blocked, log in here". |
| Spear-Phishing | Phishing targeted at a specific person or organization, often personalized using reconnaissance. | An email addressed to an accountant by name with a fake invoice attachment. |
| Malicious Attachment | A file that executes harmful code when opened. | A `.docm` with a VBA macro, an `.iso` or `.lnk` file. |
| Office Macro (VBA) | Scripts embedded in Office documents that can execute commands. | `AutoOpen()` macro calling `Shell("powershell ...")`. |
| PowerShell | Windows scripting language and shell with deep system access; frequently abused by attackers. | `powershell -nop -w hidden -enc <base64>` downloading a payload. |
| Obfuscation | Hiding the real purpose of code to evade detection. | Base64-encoded PowerShell commands or string concatenation. |
| LOLBins (Living off the Land Binaries) | Legitimate system tools abused for malicious purposes. | PowerShell, `mshta.exe`, `certutil.exe` used to download files. |
| Payload / Loader | The malicious code delivered after initial access; a loader fetches further stages. | PowerShell downloads a loader that installs a remote access tool. |
| Command and Control (C2) | Infrastructure attackers use to control compromised systems. | The IP the loader beacons to over HTTPS. |
| Credential Harvesting | Collecting usernames and passwords via fake login pages. | A cloned bank login page hosted on a lookalike domain. |
| Typosquatting / Lookalike Domain | Registering domains similar to legitimate ones to deceive users. | `kaspi-secure[.]com` instead of `kaspi.kz`. |
| Threat Hunting | Proactive, hypothesis-driven search for threats that evaded automated detection. | Hypothesis: "Office applications in our network spawn PowerShell processes." |

## References

- Recorded Future, *The Threat Intelligence Handbook*
- MITRE ATT&CK — https://attack.mitre.org
- ENISA Threat Landscape Report
- V. Costa-Gazcon, *Practical Threat Intelligence and Data-Driven Threat Hunting*, 2021
