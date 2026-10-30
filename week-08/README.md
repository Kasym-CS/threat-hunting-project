# APT29 Behavior Emulation and Windows Detection Validation

> A safe, manual Windows PowerShell lab inspired by selected behaviors documented for APT29. The project maps lab actions to MITRE ATT&CK and outlines how Windows telemetry can be reviewed. It is not a reproduction of a full APT29 intrusion.

## Project Overview

This project documents a small, controlled behavior-emulation exercise performed on a personal Windows laptop. The purpose was to study selected MITRE ATT&CK techniques associated with APT29, run harmless PowerShell-based simulations, and identify the Windows event sources that could provide evidence of those actions.

The exercise was performed manually, without a virtual machine and without MITRE CALDERA. Python 3.12.10 was available for an auxiliary local HTTP receiver bound only to `127.0.0.1`.

No malware, exploit, credential theft, unauthorized access, domain reconnaissance, lateral movement, or transfer of corporate data was used. The test data was synthetic.

## Objectives

- Review the MITRE ATT&CK profile for APT29 (Group ID `G0016`).
- Select relevant ATT&CK techniques and distinguish documented adversary behavior from the safe lab equivalents.
- Run benign PowerShell commands and review the availability of Windows PowerShell logging.
- Test a user-level Windows Run key with a harmless marker script.
- Prepare a synthetic text file and perform an optional same-host HTTP transfer test.
- Document the evidence, limitations, cleanup, and further detection-validation steps.

## ATT&CK Techniques in Scope

| ATT&CK ID | Technique | How it relates to this project |
|---|---|---|
| [T1078.003](https://attack.mitre.org/techniques/T1078/003/) | Valid Accounts: Local Accounts | APT29 has used compromised local accounts. The lab only inspected an already-authorized local user context; it did not compromise an account or reproduce an intrusion. |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | A temporary user-level Run value launched a harmless marker script at logon. The marker appearing after sign-in confirmed the behavior. |
| [T1048.002](https://attack.mitre.org/techniques/T1048/002/) | Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | Selected because MITRE maps the SolarWinds Compromise to this sub-technique. The lab's localhost HTTP test does **not** implement or validate T1048.002. |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Command and Scripting Interpreter: PowerShell | Supporting technique for the benign PowerShell commands and scripts used during the lab. |

The APT29 profile aggregates observations from multiple campaigns and time periods. A technique listed on the group profile should not be interpreted as proof that every APT29 operation used it, or that all selected techniques formed one historical attack chain.

## What Was Performed

1. Collected basic host and session context using PowerShell, including the current user, computer name, PowerShell version, and current time.
2. Checked whether the `Microsoft-Windows-PowerShell/Operational` log was enabled.
3. Ran harmless PowerShell commands and printed a unique lab marker.
4. Created a benign marker script and a temporary user-level value named `APT29-LAB` under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
5. Signed out and signed back in to the same Windows account. The marker file contained the following output, confirming that the script ran at logon:

   ```text
   APT29-LAB-PERSISTENCE 30.10.2026 1:04:49,25
   ```

6. Created a synthetic text file for a local HTTP-transfer test. A Python receiver was configured to listen on `127.0.0.1:8088`. The HTTP status and SHA-256 comparison should be recorded below only after checking the actual terminal output or saved evidence.
7. Removed the temporary Run value and the `APT29-Lab` working directory. The final path checks returned:
   - `APT29-Lab`: `False` — the working directory was removed.
   - `Documents\APT29-Lab-Evidence`: `True` — the evidence directory remained available.

## Results Status

| Test | Status supported by the available record | Notes |
|---|---|---|
| PowerShell commands executed | Performed | Basic commands and a unique marker were run. Event-log detection is a separate question. |
| User-level Run key persistence | Confirmed | The harmless marker appeared after signing out and signing back in. |
| Windows event collection | To be documented from evidence | Do not claim Event ID 4104, 4624, 4688, Sysmon events, or a SIEM alert unless the corresponding records were actually found and saved. |
| Local HTTP transfer | Verification details required | Record the actual HTTP response, received-file existence, and SHA-256 comparison from the terminal or evidence. |
| Cleanup | Confirmed | The lab directory was absent and the evidence directory remained. |
| SIEM/EDR detection | Not established | No SIEM/EDR alert should be claimed without evidence from an integrated platform. |

Suggested fields to complete after reviewing the saved terminal output:

- HTTP response status: `[enter actual value / Not verified]`
- Received file exists: `[Yes / No / Not verified]`
- SHA-256 hashes match: `[Yes / No / Not verified]`
- PowerShell Event ID 4104 found: `[Yes / No / Not checked]`
- Security Event ID 4624 found: `[Yes / No / Not checked]`
- Security Event ID 4688 found: `[Yes / No / Not checked]`
- Sysmon registry/process/network events found: `[Yes / No / Not installed or not checked]`
- SIEM/EDR alert observed: `[Yes / No / Not applicable]`

## Important Limitations

- **Initial access:** The lab used an account that was already authorized and signed in by the tester. It did not emulate credential compromise or the method by which an attacker first gains access.
- **Persistence:** The lab tested a benign user-level Run entry and then removed it. This confirms the marker's logon execution, not malicious persistence by APT29.
- **Data transfer:** A transfer to `127.0.0.1` remains on the same computer. It is not data exfiltration from the host and does not validate T1048.002 or reproduce APT29's HTTPS activity.
- **Detection:** Successful execution is not the same as successful logging, and successful logging is not the same as an EDR/SIEM alert. Each result must be evidenced separately.
- **Tooling:** MITRE CALDERA, a separate SIEM, and a separate EDR platform were not used as part of the confirmed lab record.
- **Logging configuration:** Windows events may not be present if the required audit policies, PowerShell logging, Sysmon configuration, or registry auditing were not enabled before the test.

## Environment and Tools

| Component | Use |
|---|---|
| Windows 10/11 | Test operating system |
| Windows PowerShell | Benign commands and marker-script setup |
| Windows Event Viewer | Manual review of Windows logs |
| Python 3.12.10 | Local HTTP receiver for synthetic test data |
| MITRE ATT&CK | Adversary behavior classification |
| MITRE CALDERA | Not used |
| Virtual machine | Not used |
| SIEM/EDR | Not established as part of this lab |

## Repository Structure

```text
.
├── README.md
├── apt29-emulation-plan-analysis.md
├── detection-validation-plan.md
└── evidence/
    └── README.md
```

The `evidence/` directory is intended for sanitized screenshots and exported logs. Do not commit raw corporate logs or information that identifies a real user, organization, or internal system.

## Documents

- [APT29 Emulation Plan Analysis](apt29-emulation-plan-analysis.md) — APT29 background, technique selection, lab actions, and scope limitations.
- [Detection Validation Plan](detection-validation-plan.md) — event sources, expected telemetry, validation criteria, and a results matrix.
- [Evidence folder guidance](evidence/README.md) — suggested evidence names and redaction guidance.

## References

- [MITRE ATT&CK — APT29 (G0016)](https://attack.mitre.org/groups/G0016/)
- [MITRE ATT&CK — T1078.003 Valid Accounts: Local Accounts](https://attack.mitre.org/techniques/T1078/003/)
- [MITRE ATT&CK — T1547.001 Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [MITRE ATT&CK — T1048.002 Exfiltration Over Asymmetric Encrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/002/)
- [MITRE ATT&CK — T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [Microsoft Learn — PowerShell logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging)
- [Microsoft Learn — Audit Process Creation](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing)

## Project Status

- **Project type:** Educational lab / manual behavior emulation
- **Test date:** 30 October 2026
- **Status:** Core PowerShell and persistence actions performed; event-detection and local-transfer evidence should be completed from the actual saved logs and terminal output.
