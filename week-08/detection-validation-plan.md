# Week 8 — Detection Validation Plan: PowerShell Activity on a Lab Host

**Task (syllabus §3.3):** develop a simple adversary-emulation plan and document it using MITRE ATT&CK techniques.

## 1. Scope

This week is implemented as an **authorised purple-team detection-validation test**. Safe, read-only commands reproduce the *telemetry* of selected ATT&CK techniques, and each step checks whether the lab's Sysmon + Splunk pipeline (weeks 6–7) records and detects it.

| Item | Value |
|---|---|
| Host | `HOME-PC` — the author's own standalone Windows 11 lab laptop (not domain-joined, not a work machine) |
| Account | Current user `HOME-PC\Kasym` |
| Test date | 30 October 2026, 00:00:27 – 00:01:53 (≈ 1.5 minutes) |
| Telemetry | Sysmon Event ID 1 (process creation), PowerShell Operational Event ID 4104 (Script Block Logging) → Splunk `index=main` |
| Framework | MITRE ATT&CK Enterprise |
| Command type | Read-only discovery and harmless output only; every step prints a unique marker `PS-ATTACK-SIM-T0n` |
| **Out of scope by design** | initial access, credentials, persistence, privilege escalation, disabling or changing security tools, lateral movement, data collection or exfiltration, network scanning, any real payload |

**Why the scope differs from the syllabus chain** (initial access → persistence → exfiltration): those stages change the system or move data and are not appropriate for a personal machine. The value of this exercise for a threat hunter is the *detection side* — proving which behaviours are visible in the logs and which are not.

## 2. Test plan

| Step | Tactic | ATT&CK technique | Safe command (single line) | New process? | Where it should appear |
|---|---|---|---|---|---|
| T01 | Execution | T1059.001 PowerShell | `Write-Output "PS-ATTACK-SIM-T01"` | No | 4104 |
| T02 | Discovery | T1033 System Owner/User Discovery | `Write-Output "PS-ATTACK-SIM-T02"; whoami; $env:USERDOMAIN; $env:USERNAME` | **Yes** — `whoami.exe` | 4104 + Sysmon 1 |
| T03 | Discovery | T1082 System Information Discovery | `Write-Output "PS-ATTACK-SIM-T03"; Get-CimInstance Win32_OperatingSystem \| Select-Object Caption, Version, OSArchitecture` | No | 4104 |
| T04 | Discovery | T1016 System Network Configuration Discovery | `Write-Output "PS-ATTACK-SIM-T04"; Get-NetIPConfiguration \| Select-Object InterfaceAlias, IPv4Address, DNSServer` | No | 4104 |
| T05 | Discovery | T1057 Process Discovery | `Write-Output "PS-ATTACK-SIM-T05"; Get-Process \| Select-Object -First 10 Name, Id` | No | 4104 |
| T06 | Execution / Defense Evasion | T1059.001 + T1027.010 Command Obfuscation | encoded `Write-Output "PS-ATTACK-SIM-ENCODED-OK"` run in a child `powershell.exe -NoProfile -EncodedCommand` | **Yes** — child `powershell.exe` | Sysmon 1 + 4104 (decoded) |

All commands only display information already available to the current user. Nothing is created, changed, downloaded or sent anywhere.

## 3. Verification queries (Splunk)

| Step | Query |
|---|---|
| All steps (4104) | `index=main source="*PowerShell/Operational" EventCode=4104 "PS-ATTACK-SIM" \| table _time host _raw` |
| T02 (Sysmon 1) | `index=main EventCode=1 Image="*\\whoami.exe" \| table _time host User ParentImage Image CommandLine` |
| T06 (Sysmon 1) | `index=main EventCode=1 Image="*\\powershell.exe" CommandLine="*EncodedCommand*" \| table _time host User ParentImage CommandLine` |
| T06 (4104, decoded) | `index=main source="*PowerShell/Operational" EventCode=4104 "PS-ATTACK-SIM-ENCODED-OK"` |

## 4. Results

All six steps were executed in one PowerShell session; every marker appeared in the console output.

![Console output of the test](images/w8-console.png)

| Step | Technique | Executed | Sysmon 1 | 4104 | Alerted | Verdict | Comment |
|---|---|---|---|---|---|---|---|
| T01 | T1059.001 | Pass | n/a | ✅ 00:00:27.256 | No rule | **Pass** (collected) | Plain command inside the running session — no new process |
| T02 | T1033 | Pass | ✅ `whoami.exe`, 00:00:43.458 | ✅ 00:00:43.420 | No rule | **Pass** | Only `whoami` created a process; `$env:` variables visible in 4104 only |
| T03 | T1082 | Pass | n/a | ✅ 00:00:55.014 | No rule | **Pass** (collected) | CIM query visible only in 4104 |
| T04 | T1016 | Pass | n/a | ✅ 00:01:06.200 | No rule | **Pass** (collected) | Visible only in 4104 |
| T05 | T1057 | Pass | n/a | ✅ 00:01:20.771 | No rule | **Pass** (collected) | Visible only in 4104 |
| T06 | T1059.001 / T1027.010 | Pass | ✅ child `powershell.exe -EncodedCommand`, 00:01:52.170 | ✅ decoded text, 00:01:53.621 | Not verified | **Pass** | Matches the week-7 CAR alert condition (parent ≠ `explorer.exe`); hourly alert run not checked |

**Coverage: 6 of 6 steps collected in Splunk.** Sysmon Event ID 1 saw 2 of 6 steps; PowerShell Event ID 4104 saw 6 of 6.

### Script Block Logging — the whole test in one table

All seven 4104 events of the test (six markers plus the line that prepared the encoded command):

![4104 events of the test](images/w8-4104-table.png)

### Correlating the two sources (T02)

The same step appears in both logs **38 ms apart**: 4104 at 00:00:43.420 shows what the user typed, Sysmon 1 at 00:00:43.458 shows the process it created — `whoami.exe` with parent `powershell.exe`.

![Sysmon event for whoami.exe](images/w8-whoami.png)

### Encoded command (T06) — same action, two views

| Source | Time | What the analyst sees |
|---|---|---|
| Sysmon 1 | 00:01:52.170 | `powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAC0ATwB1AHQA…` — unreadable Base64 |
| PowerShell 4104 | 00:01:53.621 | `Write-Output "PS-ATTACK-SIM-ENCODED-OK"` — readable decoded code |

The 1.5-second gap is the time the child process needed to start, decode and run the command. The 4104 event also contains the line where the command was prepared in plain text; this is an artefact of preparing it in the same session — in a real attack only the decoded block from the child process would be present.

![Sysmon event for the encoded command](images/w8-encoded.png)

## 5. Key observation — process logging alone is not enough

Only two steps start a new process (`whoami.exe` in T02 and the child `powershell.exe` in T06). Every other discovery action is a cmdlet or variable executed **inside the already running PowerShell**, so Sysmon Event ID 1 never sees it. Without Script Block Logging (4104), most PowerShell-based discovery on this host would be invisible to the SIEM.

## 6. From single events to one hunting rule

A single `whoami` or `Get-Process` is normal; several different discovery actions from the same host within a few minutes is a stronger signal ("discovery burst"):

```spl
index=main source="*PowerShell/Operational" EventCode=4104
  ("whoami" OR "Get-CimInstance" OR "Get-NetIPConfiguration" OR "Get-Process" OR "USERNAME")
| eval cmd=case(like(_raw,"%whoami%"),"whoami",
                like(_raw,"%Get-CimInstance%"),"Get-CimInstance",
                like(_raw,"%Get-NetIPConfiguration%"),"Get-NetIPConfiguration",
                like(_raw,"%Get-Process%"),"Get-Process",
                like(_raw,"%USERNAME%"),"env-user")
| bin _time span=5m
| stats dc(cmd) as distinct_discovery values(cmd) as commands by host _time
| where distinct_discovery >= 3
```

**Result:** the test window was returned as **exactly one row** — host `HOME-PC`, window 00:00, **4 distinct discovery actions** (`whoami`, `Get-CimInstance`, `Get-NetIPConfiguration`, `Get-Process`); no other windows exceeded the threshold in the same hour. The `$env:USERNAME` call was counted as `whoami` because both were typed in the same script block.

![Discovery burst correlation](images/w8-burst.png)

 Possible false positives: the AMD / ASUS utilities seen in week 7 also call `Get-CimInstance`, so the threshold and the list of commands must be tuned to the environment.

## 7. Conclusion

- All 6 test steps were executed and **all 6 were collected** in Splunk.
- **Process logging alone covered only 2 of 6 steps.** Discovery done with PowerShell cmdlets and variables runs inside the existing process and is invisible to Sysmon Event ID 1; PowerShell Script Block Logging (4104) recorded every step. For PowerShell-based activity, 4104 is a required data source, not an optional one.
- **Encoding hides a command only from the process command line.** The Base64 string in Sysmon was unreadable, but 4104 stored the decoded code 1.5 seconds later.
- **Correlating the two sources works on timestamps:** the same step appeared in both logs 38 ms apart.
- **Single discovery events have little value on their own**, but the correlation rule turned four ordinary commands into one meaningful finding: one row, one host, 4 distinct discovery actions within a five-minute window.

**Next step:** save the discovery-burst search as a scheduled alert next to the week-7 CAR alert, and tune the command list against legitimate vendor tools (e.g. AMD / ASUS utilities that also call `Get-CimInstance`).

## 8. Link to the project

| Week | Connection |
|---|---|
| 4 | Execution and Discovery follow the initial access stage in the APT29 Kill Chain |
| 6 | T06 repeats the encoded-command test with a new marker |
| 7 | T06 is the case the tuned CAR analytic (v3) is meant to catch |

## References

- MITRE ATT&CK — T1059.001, T1033, T1082, T1016, T1057, T1027.010
- Microsoft Learn — *about_Logging_Windows* (Script Block Logging, Event ID 4104)
- K. Wilhoit, *Operationalizing Threat Intelligence*, 2022
