# Week 3 — Filtering and Normalization

Raw OSINT data is noisy: the same indicator appears in different formats, feeds contain duplicates, and some "indicators" are legitimate services. Before analysis the data is cleaned in two stages.

## Stage 1 — Normalization Script (before import)

`scripts/normalize_iocs.py` takes a raw text file with mixed indicators and:

1. **Refangs** indicators (`hxxp` → `http`, `[.]` → `.`) so they can be parsed;
2. **Classifies** each line as URL, domain, IPv4, MD5, SHA-1, SHA-256 or email;
3. **Normalizes** formats (lower-case domains and hashes, strips trailing dots and whitespace);
4. **Removes duplicates**;
5. **Filters** a small allowlist of well-known legitimate domains (basic false-positive reduction);
6. Writes a **CSV ready for MISP import** and a **defanged report** safe to publish on GitHub.

```bash
python3 scripts/normalize_iocs.py raw_iocs.txt -o clean_iocs.csv -r report.md
```

![Script output](images/normalize-output.png)

| Metric | Value |
|---|---|
| Raw lines | <N> |
| Valid unique IOCs | <N> |
| Duplicates removed | <N> |
| Filtered as benign | <N> |
| Unrecognized lines | <N> |

## Stage 2 — Filtering inside MISP

- **Warninglists:** MISP marks attributes that match lists of known benign values (top domains, public DNS resolvers, cloud provider ranges). Attributes flagged by a warninglist were reviewed and <removed / kept with `to_ids` disabled>.
- **Correlation:** MISP automatically links attributes that appear in several events or feeds. <N> of my IOCs correlated with the CIRCL OSINT feed, which confirms they are known malicious.
- **to_ids flag:** only validated indicators keep `to_ids = true`, so that only they would be exported to detection systems.

![Warninglist hit](images/misp-warninglist.png)
![Correlation graph](images/misp-correlation.png)

## Conclusion

<Your short conclusion: how much noise was removed, how many indicators were confirmed by correlation, what this means for using OSINT feeds in hunting.>
