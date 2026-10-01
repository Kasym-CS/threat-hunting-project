# Week 2 — OSINT Data Collection

**Goal:** collect open-source data about infrastructure used to deliver malicious PowerShell payloads — the execution stage that follows a successful spear-phishing lure — using URLhaus, VirusTotal, Shodan and Maltego.

**Rules of engagement:** passive collection only; no scanning, login attempts or interaction with the hosts. Phishing URLs are never opened in a browser and are written defanged (`hxxp`, `[.]`).

## 1. Seed IOCs

Seed indicators were collected from **URLhaus** (abuse.ch) on 2026-10-01 by searching for entries related to PowerShell payloads (`powershell`, `tag:ps1`). Entries hosted on legitimate platforms (e.g. `raw.githubusercontent.com`) and unrelated cryptominer campaigns were excluded.

| # | Defanged URL | Host | Date added (UTC) | Status | Tags |
|---|---|---|---|---|---|
| 1 | `hxxps://true-soft[.]su/powershell/Loader.ps1` | `true-soft[.]su` | 2026-09-12 | Offline | — |
| 2 | `hxxps://genesis-softs[.]com/powershell/Genesis.ps1` | `genesis-softs[.]com` | 2026-07-11 | Offline | ps1 |
| 3 | `hxxp://192.227.152[.]240:8080/powershell.ps1` | `192.227.152[.]240` | 2025-11-05 | Offline | Cobalt Strike, obfuscated, opendir, ps1 |
| 4 | `hxxp://62.60.226[.]251/kj23klm23lksdkdksd/powershell` | `62.60.226[.]251` | 2025-11-29 | Offline | ps1 |

**Initial observations:**

- All four URLs deliver PowerShell content; payload paths openly contain the word `powershell`.
- Two hosts are domains in the `.su` and `.com` zones whose names imitate software distribution sites (`true-soft`, `genesis-softs`); the other two are bare IP addresses, one using the non-standard port 8080.
- Entry #3 is tagged as an obfuscated PowerShell script delivering **Cobalt Strike**, a post-exploitation framework commonly used after phishing-based initial access; the server also exposed an open directory listing.
- All entries are already offline, which illustrates the short lifetime of malicious infrastructure and the limited value of blocking by IOC alone.

![URLhaus search results](images/urlhaus-1.png)

## 2. Shodan

Shodan was used to look at the current state of the attacker servers. The lookup is passive: it shows Shodan's own scan results, and no traffic is sent to the host by the analyst.

| Field | `192.227.152[.]240` |
|---|---|
| Organization / ISP | HostPapa |
| ASN | AS36352 |
| Location | Buffalo, United States |
| Hostnames | `astra-ai[.]xyz`, `192-227-152-240-host.colocrossing[.]com` |
| Open ports | 22/tcp (OpenSSH 9.9), 80/tcp, 443/tcp |
| Tags | `eol-product` |
| Last seen | 2026-09-30 |

![Shodan — 192.227.152.240](images/shodan-1.png)

**Findings:**

- **The server is still alive, but the payload is gone.** The host was seen by Shodan on 2026-09-30, yet port 8080 — where URLhaus recorded the Cobalt Strike PowerShell loader in November 2025 — is no longer exposed. Only SSH (22) and web ports (80, 443) remain, the typical profile of a rented VPS administered remotely.
- **New hostname.** The IP now carries the hostname `astra-ai[.]xyz`, which does not appear in VirusTotal passive DNS. It may be new attacker infrastructure, or the IP may have been re-assigned to another customer of the provider; the indicator is therefore recorded with **low confidence**.
- **Commodity data-centre hosting.** Reverse DNS (`…host.colocrossing[.]com`) shows the address belongs to an ordinary VPS data centre, which matches the VirusTotal results: attackers rent cheap hosting rather than using compromised home devices.
- **End-of-life software.** The `eol-product` tag means at least one exposed service runs software that no longer receives security updates.

**Limitations:** the free Shodan plan restricts search filters (e.g. `asn:`, `ssl.cert.subject.cn:`), so broader infrastructure searches were not performed. Host lookups for the other IPs (`62.60.226[.]251`, `196.251.122[.]7`) are planned for the next iteration.

## 3. VirusTotal

Each host from the seed list was looked up in VirusTotal (search by domain/IP, not by URL submission) on 2026-10-01.

| Host | Detections | Network / registration | Notable relations |
|---|---|---|---|
| `192.227.152[.]240` | 8/91 (community score −13) | AS36352 HostPapa, US, range 192.227.152.0/22 | Passive DNS: `cdk[.]lat` (2026-03-28), `node1.klxyz[.]xyz` (2024-06-18); 1 communicating **PowerShell** file detected by 31/63 engines (SHA-256 begins with `f437051030243bd86e35…`); 3 historical SSL certificates incl. a *CloudFlare Origin Certificate* (2026-06-05) and one issued for `cdk[.]lat` |
| `62.60.226[.]251` | 10/91 (community score −59) | AS214351 Femo IT Solutions Limited, DE, range 62.60.226.0/24 | Passive DNS: 13 domains over 2019–2026, incl. `zen-doc.innocreed[.]com` (13/91), `cook.organzoperate[.]com` (11/91), `opendialoguetogether[.]org` (3/91), `zen-doc.toufanti[.]com`, `zen-doc.toutfmi[.]de`, `domdom[.]life` |
| `genesis-softs[.]com` | 17/91 (community score −11) | Registrar Gransy s.r.o.; domain created ~2 months before analysis | Categorised as *Malicious, Newly Registered*, *phishing and fraud* and *Malware Sites*; 5 vendors (BitDefender, G-Data, LevelBlue, SOCRadar, Sophos) label it specifically as **Phishing** |
| `true-soft[.]su` | 13/91 | Resolved to `196.251.122[.]7` (first seen 2026-09-05) | 2 communicating **PowerShell** files: `Loader.ps1` (22/61) and `sleestak_payload_1.ps1` (**0/54**); 5 referring files incl. `BorisFX-Setup-main.zip` and `Acrobat-Free-Setup-main.zip` (2/65 each) and `README.md` files |

![VirusTotal detection — 192.227.152.240](images/virustotal-1.png)
![VirusTotal relations — 192.227.152.240](images/virustotal-relations.png)
![VirusTotal detection — genesis-softs.com](images/virustotal-2.png)
![VirusTotal relations — 62.60.226.251](images/virustotal-3-relations.png)
![VirusTotal relations — true-soft.su](images/virustotal-4-relations.png)

**Findings:**

- **Low detection rates.** Even confirmed malware-distribution hosts are flagged by only 8–17 of ~91 engines (9–19 %). A defender relying on a single reputation source would most likely miss them; this supports hunting by behaviour rather than by IOC reputation alone.
- **Hosting choice.** Both IP addresses belong to commercial hosting providers (HostPapa in the US, Femo IT Solutions in Germany), i.e. attackers rent ordinary VPS infrastructure rather than using compromised home devices.
- **Infrastructure reuse.** `62.60.226[.]251` has served 13 different domains since 2019. Three of them follow the same naming pattern `zen-doc.<random-word>.<tld>` (April–June 2025), which suggests the same operator rotating domains while keeping the server — a typical pattern for document-themed lures. Most of these related domains have 0/91 detections, so pivoting through passive DNS reveals malicious infrastructure that reputation checks alone do not.
- **Hiding behind a CDN.** A Cloudflare Origin Certificate on `192.227.152[.]240` indicates the server was at some point placed behind Cloudflare, which hides the real IP from victims and defenders.
- **Direct link to the project topic.** The only file communicating with `192.227.152[.]240` is a PowerShell script detected by 31/63 engines, confirming the host's role in PowerShell-based payload delivery (Cobalt Strike tag in URLhaus).
- **Fake software lures and an undetected payload.** `true-soft[.]su` is referenced by archives named like popular software installers (`Acrobat-Free-Setup-main.zip`, `BorisFX-Setup-main.zip`; the `-main.zip` suffix matches the format of GitHub repository downloads) and serves `Loader.ps1` plus a second script, `sleestak_payload_1.ps1`, that **no engine detects (0/54)**. Here the social-engineering lure is fake free software rather than an email attachment, but the post-delivery behaviour is the same — the user runs a PowerShell loader — which is exactly what this project will hunt for.
- **Short-lived infrastructure.** `true-soft[.]su` first resolved on 2026-09-05, its payload appeared in URLhaus on 2026-09-12, and by the time of analysis it was already offline: the useful lifetime of such infrastructure is measured in days to weeks.
- **Freshly registered domain.** `genesis-softs[.]com` was registered only about two months before analysis and is already classified as phishing by several vendors — newly registered domains are a strong phishing indicator.

**New indicators discovered via pivoting:** `cdk[.]lat`, `node1.klxyz[.]xyz`, `zen-doc.innocreed[.]com`, `zen-doc.toufanti[.]com`, `zen-doc.toutfmi[.]de`, `cook.organzoperate[.]com`, `opendialoguetogether[.]org`, `dxas.dramaticdream[.]com`, `domdom[.]life`, `196.251.122[.]7`, the PowerShell file hash above, and the file names `Loader.ps1` / `sleestak_payload_1.ps1` (hashes to be added).

## 4. Maltego CE

**Method.** The relationships collected in URLhaus and VirusTotal (URL → domain → IP → autonomous system → country) were put into a table and loaded into Maltego CE with *Import a 3rd Party Table* (sequential connectivity, identical entities merged). Maltego was then used for link analysis and visualization of the whole data set.

![Maltego graph — overview](images/maltego-graph.png)
![Maltego graph — 192.227.152.240 cluster](images/maltego-graph-2.png)

**Findings:**

The graph splits into three independent clusters, i.e. at least three separate pieces of infrastructure:

| Cluster | Central node | Connected entities | Interpretation |
|---|---|---|---|
| A | `62.60.226[.]251` (AS214351, Germany) | 7 domains: `zen-doc.innocreed[.]com`, `zen-doc.toufanti[.]com`, `zen-doc.toutfmi[.]de`, `cook.organzoperate[.]com`, `opendialoguetogether[.]org`, `dxas.dramaticdream[.]com`, `domdom[.]life` + the payload URL | **Hub server.** One IP has served many short-lived domains; the repeated `zen-doc.*` pattern points to one operator rotating domains while keeping the server |
| B | `192.227.152[.]240` (AS36352, United States) | `cdk[.]lat`, `node1.klxyz[.]xyz`, `astra-ai[.]xyz` + the Cobalt Strike PowerShell URL | Smaller server with fewer domains; used for Cobalt Strike delivery |
| C | `true-soft[.]su` → `196.251.122[.]7` | `Loader.ps1` URL | Single-domain infrastructure for a fake-software lure campaign |

`genesis-softs[.]com` has no current IP resolution in the collected data and appears as a separate node.

The graph shows clearly what a list of IOCs does not: blocking one domain from cluster A would leave six others on the same server untouched, whereas blocking or monitoring the **IP** covers the whole cluster. At the same time, IPs change owners (see `astra-ai[.]xyz` in section 2), so infrastructure-based blocking is short-lived as well — another argument for hunting the attacker's *behaviour* (PowerShell execution) in later weeks.

## 5. Summary

- **4 seed IOCs** (PowerShell payload URLs from URLhaus) were enriched into **12 additional network indicators** (11 domains and 1 IP address) and **3 related PowerShell files** through passive pivoting in VirusTotal and Shodan.
- **Infrastructure patterns:** rented VPS hosting in the US and Germany; one hub IP serving many rotating domains with a shared naming scheme (`zen-doc.*`); newly registered domains imitating software sites (`true-soft`, `genesis-softs`); Cloudflare used to hide one origin server.
- **Detection gap:** reputation scores for confirmed malicious hosts are low (8–17 of ~91 engines), most pivoted domains have 0 detections, and one PowerShell payload (`sleestak_payload_1.ps1`) was not detected by any engine (0/54).
- **Short lifetime:** all seed URLs were offline at the time of analysis, and `true-soft[.]su` lived for only a few weeks.
- **Conclusion for the project:** indicator-based defence alone would miss most of this activity. This motivates the hypothesis for week 5: instead of looking for known IOCs, hunt for the behaviour they all share — a user-launched process or Office document spawning `powershell.exe` that downloads and runs a script.
- All collected indicators are passed to MISP for processing and correlation in week 3.

## References

- M. Bazzell, *Open Source Intelligence Techniques*
- OSINT Framework — https://osintframework.com
