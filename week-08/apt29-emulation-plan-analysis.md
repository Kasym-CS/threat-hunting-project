# APT29 Emulation Plan Analysis

## 1. Purpose

This document explains why APT29 was selected, maps selected adversary behaviors to MITRE ATT&CK, and describes the safe lab equivalents used in this project. The scenario focuses on PowerShell and basic Windows telemetry. It is an educational behavior-emulation exercise, not a reproduction of a full APT29 intrusion or the execution of malware.

## 2. APT29 Overview

APT29 is a threat group tracked by MITRE ATT&CK under Group ID **G0016**. The group is also associated with several other names. MITRE's profile summarizes techniques and procedures observed across different operations and time periods.

Relevant examples documented by MITRE include:

- The use of compromised local accounts to access victim networks.
- The use of Registry Run keys to establish persistence.
- The use of PowerShell, including encoded PowerShell scripts in some operations.
- The exfiltration of collected data over HTTPS during the SolarWinds Compromise.

The ATT&CK group profile aggregates observations from multiple campaigns. The presence of a technique on the profile does not mean that every technique was used in every operation, or that all techniques listed here occurred in one single attack chain.

**Primary source:** [MITRE ATT&CK — APT29 (G0016)](https://attack.mitre.org/groups/G0016/)

## 3. Selected MITRE ATT&CK Techniques

| Scenario phase | ATT&CK ID | Technique | APT29 context | Safe lab equivalent |
|---|---|---|---|---|
| Initial-access context | [T1078.003](https://attack.mitre.org/techniques/T1078/003/) | Valid Accounts: Local Accounts | MITRE reports that APT29 used compromised local accounts to access victim networks and targeted dormant or inactive accounts. | The tester used an already-authorized local account and inspected the signed-in user context. No account compromise or credential acquisition was simulated. |
| Persistence | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | MITRE reports that APT29 added Registry Run keys to establish persistence. | A temporary user-level Run value launched a harmless marker script. Its execution after a new logon was confirmed by the marker file. |
| Data-exfiltration technique selected for analysis | [T1048.002](https://attack.mitre.org/techniques/T1048/002/) | Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | MITRE maps the SolarWinds Compromise to this sub-technique and describes collected data being sent over an HTTPS request to a password-protected archive staged on a victim OWA server. | A local HTTP transfer to `127.0.0.1` was prepared as a limited file-transfer demonstration. It does **not** implement T1048.002 and is not evidence of host-to-external exfiltration. |
| Supporting execution technique | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Command and Scripting Interpreter: PowerShell | MITRE documents APT29's use of encoded PowerShell scripts in some CozyCar-related procedures and PowerShell during the SolarWinds Compromise. | Only benign PowerShell commands and a harmless marker script were used. No malicious encoded command, payload download, or remote execution was performed. |

### Technique-mapping note

T1078.003 is included as an **authorized-account context simulation**, not as proof that Initial Access was achieved by an adversary. Similarly, the local HTTP exercise is an auxiliary transfer test, not a successful emulation of the selected APT29 exfiltration technique. These distinctions are important for accurate ATT&CK mapping and reporting.

## 4. Lab Environment and Method

The work was performed manually on a personal Windows laptop. No virtual machine and no MITRE CALDERA deployment were used. Windows PowerShell and Event Viewer were used for the host-side actions and manual log review. Python 3.12.10 was available for the optional localhost HTTP receiver.

The lab was limited to a single host and synthetic data. No corporate files, passwords, personal data, exploit code, malware, external upload destinations, or lateral movement were involved.

### 4.1. Initial host checks

The initial checks recorded the current user, hostname, operating-system context, PowerShell version, and current time. The availability of the `Microsoft-Windows-PowerShell/Operational` log was also inspected.

Example commands used for basic context:

```powershell
Get-Date -Format o
$env:COMPUTERNAME
whoami
$PSVersionTable.PSVersion
```

### 4.2. Initial-access context — T1078.003 (behavioral analogue)

**Objective:** document the context of an already-authorized local account and the PowerShell activity performed after sign-in.

The following benign commands were executed:

```powershell
Write-Output "APT29-LAB-IA-01"
whoami
hostname
Get-Date -Format o
```

**Expected evidence sources:** Windows Security Event ID 4624 for a successful logon; Event ID 4688 for process creation if process-creation auditing is enabled; and PowerShell Operational Event ID 4104 if Script Block Logging was enabled.

**Interpretation boundary:** the test did not demonstrate how an attacker obtained the account or initially entered the system. It only documented an authorized user context and subsequent local PowerShell activity.

### 4.3. Persistence — T1547.001

**Objective:** check whether a user-level Registry Run entry can launch a harmless script at logon.

A marker script was created. Its only action was to append a timestamped string to `%TEMP%\APT29-LAB-PERSISTENCE.txt`. A temporary value named `APT29-LAB` was added under:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

The tester signed out and signed back in using the same Windows account, then checked the marker file. The following output was observed:

```text
APT29-LAB-PERSISTENCE 30.10.2026 1:04:49,25
```

**Result:** the marker output confirms that the harmless script ran during the subsequent logon.

**Potential evidence sources:** Sysmon Event IDs 12–14 when Sysmon is installed and configured for the relevant registry events; Windows Security Event ID 4657 when registry auditing and the required SACL are configured; and process-creation or PowerShell events if the relevant audit settings are enabled.

The marker file confirms functional execution. It does not, by itself, prove that a security event or detection alert was generated.

### 4.4. Data transfer — T1048.002 selected for analysis, not validated

**Objective:** prepare synthetic data and demonstrate a basic file transfer to a receiver on the same host.

A text file containing only synthetic values was created. A Python HTTP receiver was configured to listen on `127.0.0.1:8088`. PowerShell was used to submit the file to the local receiver. File integrity could then be checked by comparing the SHA-256 hashes of the source and received files.

**Critical limitation:** the loopback address `127.0.0.1` routes traffic within the same computer. The local HTTP test does not transfer data off-host, does not use HTTPS/TLS, and does not reproduce the APT29 procedure mapped to T1048.002. A valid test of that behavior would require a separately controlled receiving system and an authorized encrypted non-C2 channel. That activity was outside the scope of this project.

Complete these fields only after reviewing the actual command output or saved evidence:

- HTTP response status: `[actual status / Not verified]`
- Received file exists: `[Yes / No / Not verified]`
- Source and received SHA-256 hashes match: `[Yes / No / Not verified]`
- Receiver bind address: `127.0.0.1:8088`

## 5. Role of PowerShell — T1059.001

PowerShell was the primary interface for the benign commands and test actions. T1059.001 describes the command interpreter used to execute the commands; it does not replace the behavior-specific technique selected for each scenario phase.

The lab used PowerShell for local context checks, synthetic file creation, and review of test results. It did not use credential theft, defense impairment, lateral movement, payload downloads, or remote command execution.

## 6. Cleanup

After testing, the temporary `APT29-LAB` value was removed from the current user's Run key, the persistence marker file was deleted, and the `APT29-Lab` working directory was removed. The evidence directory was retained.

The final path checks returned:

```text
APT29-Lab: False
Documents\APT29-Lab-Evidence: True
```

Windows event logs were not deleted.

## 7. Conclusion

The lab confirmed that a harmless user-level Run entry could launch a marker script after the next logon. It also included benign PowerShell context checks and preparation of a localhost file-transfer test using synthetic data.

The exercise demonstrates how selected behaviors associated with APT29 can be studied safely and mapped to ATT&CK. It should not be described as a full APT29 emulation. In particular, the localhost HTTP transfer does not validate T1048.002, and using an already-authorized account does not reproduce the adversary's initial-access method.

## 8. References

- [MITRE ATT&CK — APT29 (G0016)](https://attack.mitre.org/groups/G0016/)
- [MITRE ATT&CK — T1078.003 Valid Accounts: Local Accounts](https://attack.mitre.org/techniques/T1078/003/)
- [MITRE ATT&CK — T1547.001 Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [MITRE ATT&CK — T1048.002 Exfiltration Over Asymmetric Encrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/002/)
- [MITRE ATT&CK — T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001/)
