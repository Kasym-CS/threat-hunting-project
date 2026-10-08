#!/usr/bin/env python3
"""
normalize_iocs.py — clean a raw list of IOCs before importing it into MISP.

Steps: refang -> classify -> normalize -> deduplicate -> filter benign -> export.
Outputs a CSV for MISP (columns: type,value,category,to_ids) and an optional
defanged Markdown report that is safe to commit to GitHub.

Usage:
    python3 normalize_iocs.py raw_iocs.txt -o clean_iocs.csv -r report.md
"""
import argparse
import csv
import ipaddress
import re
import sys
from collections import Counter, OrderedDict
from urllib.parse import urlparse

# Small allowlist of legitimate domains that often appear in phishing data
# (CDNs, fonts, big platforms) and would cause false positives.
BENIGN_DOMAINS = {
    "google.com", "googleapis.com", "gstatic.com", "microsoft.com",
    "office.com", "live.com", "windows.net", "cloudflare.com",
    "github.com", "apple.com", "facebook.com", "jsdelivr.net",
}

# Maps our IOC types to MISP attribute types and categories.
MISP_MAP = {
    "url": ("url", "Network activity"),
    "domain": ("domain", "Network activity"),
    "ipv4": ("ip-dst", "Network activity"),
    "md5": ("md5", "Payload delivery"),
    "sha1": ("sha1", "Payload delivery"),
    "sha256": ("sha256", "Payload delivery"),
    "email": ("email-src", "Payload delivery"),
}

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$")
EMAIL_RE = re.compile(r"^[^@\s]+@([a-z0-9-]+\.)+[a-z]{2,63}$")
HASH_RE = {32: "md5", 40: "sha1", 64: "sha256"}


def refang(value: str) -> str:
    """Turn defanged indicators back into their real form for parsing."""
    v = value.strip()
    v = re.sub(r"^hxxp", "http", v, flags=re.IGNORECASE)
    v = v.replace("[.]", ".").replace("(.)", ".").replace("[dot]", ".")
    v = v.replace("[:]", ":").replace("[@]", "@").replace("[at]", "@")
    return v


def defang(value: str) -> str:
    """Make an indicator non-clickable for publishing."""
    v = re.sub(r"^http", "hxxp", value, flags=re.IGNORECASE)
    return v.replace(".", "[.]")


def registered_part(domain: str) -> str:
    """Rough last-two-labels check used only for the benign allowlist."""
    return ".".join(domain.split(".")[-2:])


def classify(value: str):
    """Return (ioc_type, normalized_value) or (None, value) if unrecognized."""
    v = value.strip().strip("'\"").rstrip(".,;")
    if not v or v.startswith("#"):
        return None, v

    low = v.lower()
    if low.startswith(("http://", "https://")):
        parsed = urlparse(v)
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host:
            return None, v
        # normalize scheme and host, keep path/query as-is (they can be case-sensitive)
        rest = v[len(parsed.scheme) + 3 + len(parsed.netloc):]
        netloc = host + (f":{parsed.port}" if parsed.port else "")
        return "url", f"{parsed.scheme.lower()}://{netloc}{rest}"

    if re.fullmatch(r"[0-9a-fA-F]+", v) and len(v) in HASH_RE:
        return HASH_RE[len(v)], low

    try:
        ip = ipaddress.ip_address(v)
        if ip.version == 4:
            return "ipv4", str(ip)
    except ValueError:
        pass

    if EMAIL_RE.match(low):
        return "email", low

    if DOMAIN_RE.match(low.rstrip(".")):
        return "domain", low.rstrip(".")

    return None, v


def host_of(ioc_type: str, value: str) -> str:
    if ioc_type == "url":
        return (urlparse(value).hostname or "").lower()
    if ioc_type == "domain":
        return value
    if ioc_type == "email":
        return value.split("@", 1)[1]
    return ""


def is_benign(ioc_type: str, value: str) -> bool:
    if ioc_type == "ipv4":
        ip = ipaddress.ip_address(value)
        return ip.is_private or ip.is_loopback or ip.is_reserved
    host = host_of(ioc_type, value)
    return bool(host) and registered_part(host) in BENIGN_DOMAINS


def main():
    ap = argparse.ArgumentParser(description="Normalize raw IOCs for MISP import.")
    ap.add_argument("input", help="raw text file, one indicator per line")
    ap.add_argument("-o", "--output", default="clean_iocs.csv", help="CSV for MISP")
    ap.add_argument("-r", "--report", help="optional defanged Markdown report")
    args = ap.parse_args()

    with open(args.input, encoding="utf-8", errors="ignore") as f:
        lines = [ln for ln in f.read().splitlines() if ln.strip()]

    clean = OrderedDict()          # (type, value) -> None, keeps first-seen order
    stats = Counter(raw=len(lines))
    unrecognized, filtered = [], []

    for line in lines:
        ioc_type, value = classify(refang(line))
        if ioc_type is None:
            if not line.strip().startswith("#"):
                stats["unrecognized"] += 1
                unrecognized.append(line.strip())
            else:
                stats["comments"] += 1
            continue
        if is_benign(ioc_type, value):
            stats["filtered_benign"] += 1
            filtered.append(value)
            continue
        key = (ioc_type, value)
        if key in clean:
            stats["duplicates"] += 1
            continue
        clean[key] = None

    with open(args.output, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["type", "value", "category", "to_ids"])
        for ioc_type, value in clean:
            misp_type, category = MISP_MAP[ioc_type]
            w.writerow([misp_type, value, category, "1"])

    by_type = Counter(t for t, _ in clean)
    print(f"Raw lines:          {stats['raw']}")
    print(f"Comments skipped:   {stats['comments']}")
    print(f"Duplicates removed: {stats['duplicates']}")
    print(f"Filtered (benign):  {stats['filtered_benign']}")
    print(f"Unrecognized:       {stats['unrecognized']}")
    print(f"Clean unique IOCs:  {len(clean)}")
    for t, n in sorted(by_type.items()):
        print(f"  - {t}: {n}")
    print(f"CSV written to {args.output}")

    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            f.write("# Normalized IOC Report (defanged)\n\n")
            f.write("| Metric | Value |\n|---|---|\n")
            for k in ("raw", "comments", "duplicates", "filtered_benign", "unrecognized"):
                f.write(f"| {k} | {stats[k]} |\n")
            f.write(f"| clean_unique | {len(clean)} |\n\n")
            f.write("| Type | Indicator (defanged) |\n|---|---|\n")
            for ioc_type, value in clean:
                shown = value if ioc_type in ("md5", "sha1", "sha256") else defang(value)
                f.write(f"| {ioc_type} | `{shown}` |\n")
            if unrecognized:
                f.write("\n## Unrecognized lines\n\n")
                for u in unrecognized:
                    f.write(f"- `{defang(u)}`\n")
        print(f"Report written to {args.report}")


if __name__ == "__main__":
    sys.exit(main())
