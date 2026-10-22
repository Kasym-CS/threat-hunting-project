## T1059.001 — PowerShell

**MITRE ATT&CK Tactic:** Execution (TA0002)  
**Technique:** Command and Scripting Interpreter: PowerShell (T1059.001)  
**Platform:** Windows

### Description
PowerShell is a Windows command-line shell and scripting language used for system administration and automation. Attackers abuse PowerShell to execute malicious commands and scripts, often blending their activities with legitimate administrative operations.

### Why Attackers Use PowerShell
- **Command Execution:** Run malicious scripts and system commands.
- **Defense Evasion:** Obfuscate commands and attempt to bypass security controls.
- **Fileless Attacks:** Execute malicious code directly in memory.
- **System Reconnaissance:** Collect information about users, processes, and system configurations.
- **Payload Delivery:** Download and execute additional malicious components.
- **Lateral Movement:** Execute commands on remote systems using PowerShell Remoting.

**Key Point:** PowerShell is a legitimate administrative tool, so its execution alone does not indicate malicious activity. Analysts must examine command-line arguments, parent processes, and execution context.

**Reference:** [MITRE ATT&CK — T1059.001](https://attack.mitre.org/techniques/T1059/001/)

## Data Sources for Detection

| Source | Event ID | What it records | Key fields for the analyst |
|---|---|---|---|
| Sysmon | **1 — Process Create** | Every process start, with full command line and parent process | `Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `User`, `Hashes` |
| PowerShell Operational | **4104 — Script Block Logging** | The text of PowerShell code actually executed, recorded after decoding | `ScriptBlockText`, `ScriptBlockId`, `Path` |

**Sysmon Event ID 1** answers *who started PowerShell, from where, and with which parameters*.
The most valuable field is the parent process: PowerShell started by a user from Explorer
or a terminal is normal, while PowerShell started by an Office application or a script host
needs a closer look. Location: *Microsoft → Windows → Sysmon → Operational*.

**PowerShell Event ID 4104** answers *what the script actually did*. Because PowerShell logs
the script block after decoding, it shows readable code even when the command line itself
was encoded, which makes it the most useful source for investigations.
It is enabled through Group Policy or the registry key
`HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`
(`EnableScriptBlockLogging = 1`). Location: *Microsoft → Windows → PowerShell → Operational*.

**Correlation.** The two sources complement each other: Event 1 gives the process context
(parent, user, time), and Event 4104 gives the content. Linking them by host and time,
and adding Sysmon Event 3 (network connections) and Event 22 (DNS queries), shows the full
chain from launch to any network activity.

In this project both sources are collected into Splunk (index `main`) on the Windows 11 lab machine.

## Mitigations

| ATT&CK ID | Mitigation | How it applies to PowerShell |
|---|---|---|
| M1049 | Antivirus / Antimalware | **AMSI** lets Microsoft Defender scan PowerShell code in memory before it runs, including decoded content |
| M1038 | Execution Prevention | **AppLocker / Windows Defender Application Control** restrict which scripts may run; PowerShell then works in **Constrained Language Mode** for untrusted code |
| M1042 | Disable or Remove Feature | Remove the legacy **PowerShell v2** engine, which lacks modern logging and AMSI support |
| M1045 | Code Signing | Execution policy `AllSigned` permits only signed scripts in managed environments |
| M1026 | Privileged Account Management | **Just Enough Administration (JEA)** limits which commands administrators can run remotely |
| — | Logging | Enable Script Block Logging (4104), Module Logging (4103) and Transcription, and forward the logs to a SIEM |
| — | User execution controls | Block Office macros in files from the Internet and restrict opening shortcut / script files from email attachments, which cuts the delivery chain seen in weeks 2 and 4 |

No single control is enough: logging makes activity visible, AMSI and application control
reduce what can run, and blocking risky file types stops the chain before PowerShell starts.

**Sources:** MITRE ATT&CK T1059.001 (Detection and Mitigations sections);
Microsoft Learn — *about_Logging_Windows*, *PowerShell security features*.
