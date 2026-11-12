# Week 10 — Capstone: APT29 Emulation and Project Summary

**Task (syllabus §3.3):** emulate the TTPs of a chosen APT group (APT29) and produce a final project report tying the whole threat-hunting project together.

## 1. The group: APT29

**APT29** (MITRE ATT&CK group **G0016**, also "Cozy Bear" / "The Dukes") is a state-sponsored espionage group. It is chosen as the capstone target because its intrusion style matches this project's topic from week 1:

- initial access through **spear-phishing** (the project's theme);
- execution and payload delivery through **PowerShell** (the project's core technique, T1059.001);
- use of **Cobalt Strike** after initial access (the same framework found on live infrastructure in week 2).

APT29 is therefore the natural "real adversary" to tie the project together: the whole project has, in effect, been studying and detecting APT29-style behaviour.

## 2. Emulation approach

A full intrusion chain is documented from MITRE's **published APT29 emulation plan** (Center for Threat-Informed Defense), rather than executed end-to-end. The project's practical work validated the **Execution** and **Discovery** parts of that chain on a lab host; the remaining phases are documented from the published plan and mapped to ATT&CK.

### APT29 intrusion chain mapped to ATT&CK

| Kill-chain stage | ATT&CK tactic | Representative techniques | Detected in this project? |
|---|---|---|---|
| Initial Access | Initial Access | T1566.001 Spearphishing Attachment; T1204.002 User Execution | Documented (weeks 2, 4) |
| Execution | Execution | **T1059.001 PowerShell**; T1059.003 Windows Command Shell | ✅ detected (weeks 6, 8, 9) |
| Defense Evasion | Defense Evasion | T1027 Obfuscation; T1140 Deobfuscate/Decode | ✅ detected (encoded-command tests) |
| Discovery | Discovery | T1033 User; T1082 System Info; T1016 Network; T1057 Process | ✅ detected (week 8) |
| Persistence | Persistence | T1547.001 Registry Run Keys; T1053.005 Scheduled Task | Documented (week 8 plan) |
| Command & Control | Command and Control | T1071.001 Web Protocols; T1573 Encrypted Channel | Documented (week 2 infra) |
| Collection / Exfiltration | Collection / Exfiltration | T1005 Data from Local System; T1041 Exfil over C2 | Documented (week 8 plan) |

## 3. The project end to end

The ten weeks follow the full intelligence-to-detection cycle for one threat: spear-phishing that leads to malicious PowerShell.

| Week | Topic | What was produced | Key techniques |
|---|---|---|---|
| 1 | CTI Fundamentals | Glossary (37 terms), threat & source classification, ENISA reading | — |
| 2 | OSINT Collection | 4 seed IOCs → 12 pivots; Shodan, VirusTotal, Maltego graph; 3 infrastructure clusters | T1566, T1059.001, T1105 |
| 3 | Data Processing | MISP deployed (Docker); IOCs imported, normalised (41→20) with a Python script; warninglists, feeds | — |
| 4 | Cyber Kill Chain | APT29 2018 phishing campaign mapped to 7 stages and 19 ATT&CK techniques | T1566.002, T1059.001, T1105 |
| 5 | Hunting Hypotheses | Three hypotheses on malicious PowerShell behaviour | T1059.001 |
| 6 | ATT&CK Technique | T1059.001 studied; encoded-command test; Sysmon + Splunk lab built | T1059.001, T1027 |
| 7 | MITRE CAR | CAR-2014-04-003 implemented in Splunk as a scheduled alert; tuned for false positives | T1059.001 |
| 8 | Adversary Emulation | APT29 plan analysis + detection-validation test (Execution, Discovery) | T1059.001, T1033, T1082, T1016 |
| 9 | Atomic Red Team | T1059.001 atomics (#13, #16, #17) run; detection-coverage matrix | T1059.001, T1027 |
| 10 | Capstone | This report: APT29 emulation summary + full project synthesis | APT29 (G0016) |

## 4. Detection coverage — final picture

| ATT&CK tactic | Covered by detection in this project | Evidence |
|---|---|---|
| Execution (T1059.001) | ✅ Strong | Sysmon 1 + PowerShell 4104; CAR alert; atomic tests |
| Defense Evasion (T1027, encoded) | ✅ Partial — needs 4104 | encoded-command tests, weeks 6/8/9 |
| Discovery (T1033/T1082/T1016/T1057) | ✅ Yes, via 4104 + correlation | week 8 |
| Initial Access, Persistence, C2, Exfiltration | ⚠️ Documented, not instrumented on the lab host | weeks 2, 4, 8 (plan) |

**Honest gap analysis.** The lab host detects the Execution and Discovery phases of the APT29 chain well, because those are where instrumentation (Sysmon, Script Block Logging) was focused. Initial access (email), persistence and exfiltration would need additional data sources (email gateway, registry auditing, network/proxy logs) to be detected — a realistic finding for a single-host lab.

## 5. Key lessons of the project

1. **Indicators age; behaviour persists.** In week 2 the malicious domains and hashes were barely detected and short-lived, while the *behaviour* — PowerShell launched from a user-opened file — stayed constant. This is why the project shifted from IOC collection to behaviour-based hunting.
2. **Two data sources beat one.** Sysmon shows *that* PowerShell ran; Script Block Logging (4104) shows *what* it ran, even when the command was Base64-encoded. Neither alone is enough.
3. **Off-the-shelf detections need tuning.** The CAR analytic (week 7) produced 392 events, almost all benign; it became useful only after tuning to the environment.
4. **A testing tool leaves its own tracks.** Atomic Red Team's setup generated PowerShell and even disabled Defender monitoring — the analyst must separate tool noise from the technique under test.

## 6. Conclusion

The project took one real threat — spear-phishing leading to malicious PowerShell, as used by APT29 — through the full cycle: collecting intelligence (weeks 1–3), modelling the attack (weeks 4–5), building detections (weeks 6–7) and validating them against emulated and atomic tests (weeks 8–9). The capstone shows that the project's detection pipeline reliably covers the **Execution and Discovery** phases of an APT29-style intrusion, and identifies clearly which further data sources would be needed to cover the rest. The core technique, T1059.001 PowerShell, is detected by three independent methods.

## References

- MITRE ATT&CK — APT29 (G0016): https://attack.mitre.org/groups/G0016/
- MITRE Center for Threat-Informed Defense — Adversary Emulation Library (APT29): https://ctid.mitre.org/resources/adversary-emulation-library/
- MITRE ATT&CK — T1059.001 PowerShell: https://attack.mitre.org/techniques/T1059/001/
- FireEye/Mandiant — *Not So Cozy: A Suspected APT29 Phishing Campaign* (week 4 source)
