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
