# Week 8 (Part A) — Analysis of the Published MITRE APT29 Emulation Plan

**Task (syllabus §3.3):** develop a simple adversary-emulation plan (initial access → persistence → data exfiltration) and document it using MITRE ATT&CK techniques.

This part documents a real, **published** adversary-emulation plan rather than inventing one: the **MITRE Center for Threat-Informed Defense APT29 emulation plan**. Documenting an existing, authoritative plan satisfies the "develop and document a plan" requirement and ties directly to the project — APT29 is the group analysed in the week-4 Kill Chain and is the subject of week 10.

## Why APT29

- APT29 (G0016, "Cozy Bear") is a well-documented state-sponsored group whose intrusions begin with **spear-phishing** and rely heavily on **PowerShell** — the exact chain this project follows since week 1.
- MITRE has published a full, free emulation plan for it, so the techniques below are taken from an authoritative source, not assembled by guesswork.

## The emulation plan mapped to ATT&CK

The published plan is organised as an end-to-end intrusion. The table lists its phases and representative ATT&CK techniques, following the syllabus structure *initial access → persistence → data exfiltration*.

| Phase | ATT&CK tactic | Representative techniques (ID) | What the plan describes at this phase |
|---|---|---|---|
| Initial Access | Initial Access (TA0001) | T1566.001 Spearphishing Attachment; T1204.002 User Execution: Malicious File | A user opens a delivered file, starting code execution |
| Execution | Execution (TA0002) | **T1059.001 PowerShell**; T1059.003 Windows Command Shell | Scripted commands run on the host (the project's core technique) |
| Defense Evasion | Defense Evasion (TA0005) | T1027 Obfuscated Files or Information; T1140 Deobfuscate/Decode | Payloads and commands are encoded/obfuscated |
| Discovery | Discovery (TA0007) | T1033 System Owner/User; T1082 System Information; T1016 Network Config; T1057 Process | The actor profiles the host and environment |
| Persistence | Persistence (TA0003) | **T1547.001 Registry Run Keys / Startup Folder**; T1053.005 Scheduled Task | Code is set to run again automatically after reboot or logon |
| Collection | Collection (TA0009) | T1005 Data from Local System; T1560 Archive Collected Data | Files of interest are gathered and packaged |
| Command and Control | Command and Control (TA0011) | T1071.001 Web Protocols; T1573 Encrypted Channel | The host talks to attacker infrastructure |
| Exfiltration | Exfiltration (TA0010) | T1041 Exfiltration Over C2 Channel; T1567 Exfiltration Over Web Service | Collected data leaves the host |

*Technique IDs are from MITRE ATT&CK for APT29 (G0016) and the published emulation plan. This table is a description of that plan, not an execution guide.*

## How the plan connects to the detection work

The point of studying the plan, for a threat hunter, is to ask **which phases my monitoring can already see**. Part B of week 8 (`detection-validation-plan.md`) tested the safe, read-only parts of this chain — Execution and Discovery — on the lab host and confirmed detection in Splunk:

| Plan phase | Covered by the week-8 detection test? | Evidence |
|---|---|---|
| Execution (T1059.001) | ✅ tested (encoded PowerShell) | Sysmon 1 + PowerShell 4104 |
| Discovery (T1033/T1082/T1016/T1057) | ✅ tested | PowerShell 4104 + correlation rule |
| Initial Access, Persistence, Collection, C2, Exfiltration | ✅ tested on this host | out of scope — see Part B rules of engagement |

This shows honestly where the lab's detection coverage is strong (Execution, Discovery) and where it is not yet instrumented (persistence, exfiltration), which is itself a useful hunting finding.

## Conclusion

A complete initial-access → persistence → exfiltration plan exists and is documented here through MITRE's published APT29 emulation plan and its ATT&CK techniques. The project's own practical contribution is on the **detection** side (Part B): verifying that the Execution and Discovery phases of this chain are visible in the Sysmon + Splunk pipeline built in weeks 6–7.

## References

- MITRE Center for Threat-Informed Defense — Adversary Emulation Library, APT29 plan: https://ctid.mitre.org/resources/adversary-emulation-library/
- MITRE ATT&CK — APT29 (G0016): https://attack.mitre.org/groups/G0016/
- MITRE ATT&CK — T1059.001, T1547.001, T1041 (technique pages)
- K. Wilhoit, *Operationalizing Threat Intelligence*, 2022
