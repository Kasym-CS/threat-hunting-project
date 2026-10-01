# Week 2 — Data Source Mapping

Mapping of data sources used in this project: what each source provides, how reliable it is and where it is used.

| Source | Open / Closed | Data type | Format | Reliability | Update frequency | Use in project |
|---|---|---|---|---|---|---|
| OpenPhish (community feed) | Open | Phishing URLs | TXT | Medium–High | Frequent (hours) | Not used in this iteration |
| URLhaus (abuse.ch) | Open | Malware distribution URLs, payload hashes | CSV / JSON / API | High | Near real-time | **Used:** source of all 4 seed IOCs (wk 2) |
| PhishTank | Open | Community-verified phishing URLs | JSON / CSV | Medium (crowd-verified) | Hourly | Not used in this iteration |
| crt.sh | Open | Certificate Transparency logs | Web / JSON | High (raw facts) | Real-time | Not used in this iteration |
| Shodan | Open (free tier limited) | Internet-exposed hosts, banners, certificates | Web / API | High (raw scan data) | Continuous | **Used:** current state of attacker server (open ports, hostnames) |
| VirusTotal | Open (public API limited) | Multi-engine verdicts, relations, passive DNS | Web / API | Medium–High | Real-time | **Used:** detections, passive DNS, related files for all seed hosts |
| Maltego CE | Open (tool) | Link analysis via transforms | Graph | Depends on transform | On demand | **Used:** link analysis and visualization of collected relations |
| MISP default feeds (CIRCL OSINT) | Open | Curated IOCs and events | MISP JSON | High | Daily | Correlation in MISP |
| MITRE ATT&CK | Open | TTP knowledge base | Web / STIX | High | Several releases per year | TTP mapping (wk 4, 6, 10) |
| ENISA / CERT-KZ advisories | Open | Strategic and operational intelligence | PDF / Web | High | Annual / ad hoc | Context and landscape |
| Sysmon & PowerShell logs (lab) | Closed (internal) | Process creation, script blocks | EVTX / JSON | High | Real-time | Hunting (wk 5–9) |
| Commercial TI feeds | Closed | Curated IOCs, actor reports | API | High | Real-time | Not used (cost); noted as limitation |

## Open-Source vs. Closed-Source Data

| Aspect | Open source | Closed source |
|---|---|---|
| Cost | Free or freemium | Paid licences or internal effort |
| Coverage | Broad, but noisy | Narrower, curated or organization-specific |
| Reliability | Needs validation; false positives common | Usually higher confidence |
| Context | Often raw indicators only | Often includes attribution and context |
| Example | OpenPhish, Shodan | Internal email gateway logs, paid feeds |

**Conclusion:** for a student project open sources provide enough data for collection and correlation, but every indicator has to be validated (VirusTotal, warninglists in MISP) because open feeds contain stale and false-positive entries. Internal logs (weeks 5–9) give the most reliable evidence of actual compromise.
