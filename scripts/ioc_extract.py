#!/usr/bin/env python3
"""Extract and defang indicators of compromise (IOCs) from incident evidence.

Reads from files or stdin. Extracts IPv4, IPv6, domains, URLs, email addresses,
and file hashes (MD5/SHA1/SHA256). Output is **defanged by default** so a report
or downstream tool never accidentally resolves/visits an attacker indicator
(Security Policy §2). `--defang` forces defanging on (the default); `--no-defang`
emits raw values for feeding another tool. `--public-only` drops
private/reserved IPs so only externally meaningful indicators go to enrichment.

This tool treats all input as untrusted DATA. It never executes, fetches, or
resolves anything — it only pattern-matches text. Adapted from the
security-analyst role's ioc_extract.py.

Usage:
  ioc_extract.py suspect.strings syslog           # files
  cat alert.json | ioc_extract.py                 # stdin
  ioc_extract.py --json --public-only evidence.txt
  ioc_extract.py --defang --json evidence.txt     # explicit defang (default)
  ioc_extract.py --no-defang evidence.txt         # raw (e.g. to feed another tool)

Exit: 0 if any IOCs found, 1 if none, 3 usage error.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import sys

import re

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b")
URL_RE = re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
DOMAIN_RE = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b"
)
MD5_RE = re.compile(r"\b[A-Fa-f0-9]{32}\b")
SHA1_RE = re.compile(r"\b[A-Fa-f0-9]{40}\b")
SHA256_RE = re.compile(r"\b[A-Fa-f0-9]{64}\b")

# Avoid flagging common file extensions as TLDs.
_NON_DOMAIN_TLD = {"log", "txt", "json", "conf", "py", "sh", "md", "gz", "exe", "dll"}


def _valid_ipv4(s: str) -> bool:
    try:
        ipaddress.IPv4Address(s)
        return True
    except ValueError:
        return False


def _valid_ipv6(s: str) -> bool:
    # The loose IPV6_RE also matches syslog times like "10:01:02"; validate with
    # ipaddress so only real IPv6 addresses survive.
    try:
        ipaddress.IPv6Address(s)
        return True
    except ValueError:
        return False


# Non-routable ranges we drop under --public-only. Deliberately explicit rather
# than ipaddress.is_private: newer Python folds RFC5737 documentation ranges
# (198.51.100.0/24 etc.) into is_private, but those never appear as real
# external attacker indicators and we want the filter to key on "can't be a real
# routable external host" — RFC1918, loopback, link-local, multicast, CGNAT.
_NON_ROUTABLE = [
    ipaddress.ip_network(n) for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",   # RFC1918
        "127.0.0.0/8",                                       # loopback
        "169.254.0.0/16",                                    # link-local
        "100.64.0.0/10",                                     # CGNAT (RFC6598)
        "224.0.0.0/4",                                       # multicast
        "0.0.0.0/8",                                         # "this" network
        "::1/128", "fe80::/10", "fc00::/7", "ff00::/8",      # IPv6 equivalents
    )
]


def _is_public(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not any(obj in net for net in _NON_ROUTABLE)


def defang(kind: str, value: str) -> str:
    if kind == "ipv6":
        return value.replace(":", "[:]")
    if kind == "ipv4":
        return value.replace(".", "[.]")
    if kind == "url":
        return (value.replace("https://", "hxxps://").replace("http://", "hxxp://")
                .replace(".", "[.]"))
    if kind in ("domain", "email"):
        return value.replace(".", "[.]").replace("@", "[at]")
    return value


def extract(text: str, public_only: bool = False) -> dict:
    hashes_sha256 = set(SHA256_RE.findall(text))
    hashes_sha1 = set(SHA1_RE.findall(text)) - hashes_sha256
    hashes_md5 = set(MD5_RE.findall(text)) - hashes_sha256 - hashes_sha1

    ipv4 = {ip for ip in IPV4_RE.findall(text) if _valid_ipv4(ip)}
    if public_only:
        ipv4 = {ip for ip in ipv4 if _is_public(ip)}

    urls = set(URL_RE.findall(text))
    emails = set(EMAIL_RE.findall(text))

    # Domains: drop those that are actually email hosts, URL hosts, or filenames.
    email_hosts = {e.split("@", 1)[1] for e in emails}
    domains = set()
    for d in DOMAIN_RE.findall(text):
        tld = d.rsplit(".", 1)[-1].lower()
        if tld in _NON_DOMAIN_TLD:
            continue
        if _valid_ipv4(d):  # e.g. "1.2.3.4" matches domain regex loosely
            continue
        if d in email_hosts:
            continue
        domains.add(d)

    return {
        "ipv4": sorted(ipv4),
        "ipv6": sorted({ip for ip in IPV6_RE.findall(text) if _valid_ipv6(ip)}),
        "url": sorted(urls),
        "domain": sorted(domains),
        "email": sorted(emails),
        "md5": sorted(hashes_md5),
        "sha1": sorted(hashes_sha1),
        "sha256": sorted(hashes_sha256),
    }


def apply_defang(iocs: dict, enabled: bool) -> dict:
    if not enabled:
        return iocs
    out = {}
    for kind, values in iocs.items():
        if kind in ("md5", "sha1", "sha256"):
            out[kind] = values  # hashes are safe as-is
        else:
            out[kind] = [defang(kind, v) for v in values]
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Extract and defang IOCs from text")
    ap.add_argument("files", nargs="*", help="input files; omit to read stdin")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--public-only", action="store_true", help="drop private/reserved IPs")
    ap.add_argument("--defang", action="store_true",
                    help="defang indicators (the default; explicit for clarity)")
    ap.add_argument("--no-defang", action="store_true", help="output raw indicators")
    args = ap.parse_args(argv)

    if args.defang and args.no_defang:
        print("error: --defang and --no-defang are mutually exclusive", file=sys.stderr)
        return 3

    if args.files:
        chunks = []
        for p in args.files:
            try:
                with open(p, encoding="utf-8-sig", errors="replace") as f:
                    chunks.append(f.read())
            except OSError as e:
                print(f"error reading {p}: {e}", file=sys.stderr)
                return 3
        text = "\n".join(chunks)
    else:
        text = sys.stdin.read()

    iocs = extract(text, public_only=args.public_only)
    iocs = apply_defang(iocs, enabled=not args.no_defang)

    total = sum(len(v) for v in iocs.values())
    if args.json:
        print(json.dumps(iocs, indent=2))
    else:
        for kind, values in iocs.items():
            if values:
                print(f"[{kind}] ({len(values)})")
                for v in values:
                    print(f"  {v}")
    return 0 if total else 1


if __name__ == "__main__":
    raise SystemExit(main())
