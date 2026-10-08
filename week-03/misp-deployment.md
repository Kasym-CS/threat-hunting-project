# Week 3 — MISP Deployment and IOC Import

## 1. Environment

| Component | Version / details |
|---|---|
| Host OS | <e.g. Windows 11 + WSL2 / Ubuntu 24.04> |
| Docker | <version> |
| MISP | misp-docker, <version shown in MISP footer> |
| RAM allocated | <e.g. 8 GB> |

## 2. Deployment Steps

```bash
git clone https://github.com/MISP/misp-docker.git
cd misp-docker
cp template.env .env        # set BASE_URL, admin email and password here
docker compose pull
docker compose up -d
docker compose ps           # wait until all containers are healthy
```

Web interface: `https://localhost` (self-signed certificate warning is expected).

![MISP login](images/misp-login.png)

## 3. Creating the Event

| Field | Value |
|---|---|
| Event info | Spear-phishing infrastructure collected via OSINT (Week 2) |
| Distribution | Your organisation only |
| Threat level | Medium |
| Analysis | Initial |
| Tags | `tlp:green`, `misp-galaxy:mitre-attack-pattern="Phishing - T1566"` |

Attributes added: phishing URLs, domains, IPs and payload hashes from week 2 (cleaned with `scripts/normalize_iocs.py`, see [normalization.md](normalization.md)).

![MISP event](images/misp-event.png)

## 4. Enabling Feeds

Sync Actions → Feeds → *Load default feed metadata* → enable **CIRCL OSINT Feed** (and optionally abuse.ch feeds) → *Fetch and store all feed data*.

![MISP feeds](images/misp-feeds.png)

## 5. Problems and Solutions

| Problem | Solution |
|---|---|
| <e.g. containers restarting due to low memory> | <e.g. increased Docker RAM limit to 8 GB> |

## References

- MISP Training Documentation — https://www.misp-project.org/misp-training/
