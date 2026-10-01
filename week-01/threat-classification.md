# Week 1 — Classification of Threats and Their Sources

## 1\. Threat Actors Relevant to Spear-Phishing

|Actor type|Motivation|Skill level|How they use phishing|Example|
|-|-|-|-|-|
|Nation-state (APT)|Espionage, political influence|High|Highly targeted spear-phishing with custom malware and careful pretexts|APT29 (G0016)|
|Organized cybercrime|Financial gain|Medium–High|Malware delivery (loaders, ransomware precursors) via malicious attachments|Ransomware affiliates using phishing for initial access|
|Phishing-as-a-Service operators|Financial gain (selling kits/access)|Medium|Sell ready-made phishing kits and hosting to less skilled criminals|Credential-phishing kits imitating banks|
|Low-skill fraudsters|Quick financial gain|Low|Mass phishing via SMS/email/messengers using bought kits|Fake bank or delivery-service messages|
|Hacktivists|Ideology, publicity|Low–Medium|Phishing to steal accounts for defacement or leaks|Account takeover of an organization's social media|
|Insiders|Revenge, money|Varies|Rarely phish; may leak data used for targeted phishing|An employee leaking a staff contact list|

## 2\. Types of Phishing Threats

|Type|Channel|Goal|Related ATT\&CK|
|-|-|-|-|
|Spear-phishing attachment|Email|Code execution|T1566.001|
|Spear-phishing link|Email|Credential theft or malware download|T1566.002|
|Spear-phishing via service|Messengers, social networks|Code execution or credentials|T1566.003|
|Smishing / vishing|SMS / phone|Credentials, OTP codes|T1598 (Phishing for Information)|
|Business Email Compromise|Compromised or spoofed corporate email|Fraudulent payments|T1534 (Internal Spearphishing)|

## 3\. Sources of Threat Intelligence

|Source category|Open / Closed|Examples|What it gives this project|
|-|-|-|-|
|Internal|Closed|Email gateway logs, Sysmon, PowerShell logs, SIEM|Evidence of phishing reaching users and PowerShell execution (weeks 5–9)|
|OSINT|Open|Shodan, VirusTotal (public), crt.sh, OpenPhish, URLhaus, PhishTank|Phishing domains, URLs, hosting infrastructure|
|Vendor reports|Open|Mandiant, CrowdStrike, Microsoft, Kaspersky reports|Campaign descriptions and TTPs|
|Frameworks|Open|MITRE ATT\&CK, MITRE CAR|TTP mapping and detection analytics|
|Government / CERT|Open|ENISA, CERT-KZ (cert.gov.kz), CISA|Threat landscape, advisories|
|Commercial feeds|Closed|Paid TI platforms|Curated, high-confidence IOCs (not used — out of budget)|
|Sharing communities|Semi-closed|MISP communities, ISACs|IOCs shared between organizations|

## 4\. Notes from the ENISA Threat Landscape Report

> According to the \*ENISA Threat Landscape 2025\*, phishing remained the leading initial intrusion vector, accounting for approximately 60% of observed cases. Attackers used phishing for credential theft, session hijacking, malware delivery and command execution. ENISA also highlights the evolution of phishing techniques, including Phishing-as-a-Service (PhaaS), QR-code phishing and ClickFix-style attacks. In ClickFix attacks, victims are presented with fake CAPTCHA or verification prompts that trick them into manually executing malicious PowerShell commands. The report also shows that public administration was the most targeted sector in the EU at 38.2%, followed by transport (7.5%), digital infrastructure and services (4.8%), finance (4.5%) and manufacturing (2.9%). (\*ENISA Threat Landscape 2025\*, pp. 10, 15).



Another important trend is the increasing use of artificial intelligence in phishing and social engineering. ENISA reports that by early 2025, AI-supported phishing campaigns represented more than 80% of observed social engineering activity worldwide. Attackers are using AI and large language models to improve and automate malicious activities, including the creation of more convincing phishing content. This trend is directly relevant to this project because AI can make phishing messages more realistic and scalable, making traditional content-based detection less reliable and increasing the importance of detecting technical indicators and suspicious post-delivery behaviour. (\*ENISA Threat Landscape 2025\*, pp. 5, 13).> - where phishing / social engineering ranks among the prime threats;
> - which sectors and techniques the report highlights;
> - one trend relevant to this project (e.g. use of AI to generate phishing content).
>
> Cite the exact edition (e.g. \*ENISA Threat Landscape 2025\*) and page numbers.

## 5\. Conclusion

Spear-phishing is used by every actor type in the table, from low-skill fraudsters to APT groups, which makes it a good subject for threat hunting: the delivery method varies, but the post-delivery behaviour (Office or a script host launching PowerShell) is relatively stable and therefore huntable. This observation drives the hypothesis for week 5.

