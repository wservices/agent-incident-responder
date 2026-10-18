#!/usr/bin/env python3
"""SAFE static triage of a suspect file — NO execution, ever.

Computes cryptographic hashes, identifies the file type by magic bytes, extracts
printable strings, and raises heuristic flags for embedded URLs/IPs and
suspicious API/command names found in those strings. It only READS bytes: it
never runs, opens, detonates, unpacks, or imports the sample, and never fetches a
URL or resolves a domain found inside it (Security Policy §2). A clean result is
not proof of safety — dynamic analysis belongs in an isolated sandbox.

Usage:
  static_triage.py suspect.sample
  static_triage.py --min-len 8 --json suspect.sample
  static_triage.py --strings suspect.sample        # also dump extracted strings

Exit: 0 if a file was triaged, 3 usage/read error.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys

import re

# Magic-byte signatures (prefix match) → human label. Order matters: more
# specific prefixes are checked before generic ones.
_MAGIC = [
    (b"\x7fELF", "ELF executable"),
    (b"MZ", "PE/DOS executable (MZ)"),
    (b"%PDF", "PDF document"),
    (b"PK\x03\x04", "ZIP/Office archive"),
    (b"PK\x05\x06", "ZIP (empty archive)"),
    (b"\x1f\x8b", "gzip compressed"),
    (b"BZh", "bzip2 compressed"),
    (b"\xfd7zXZ\x00", "xz compressed"),
    (b"7z\xbc\xaf\x27\x1c", "7-zip archive"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"\xca\xfe\xba\xbe", "Java class / Mach-O fat"),
    (b"\xd0\xcf\x11\xe0", "OLE/legacy Office (CFBF)"),
    (b"#!", "script (shebang)"),
]

# Exclude control bytes (<= 0x20) and quotes/brackets so a URL does not run past
# a NUL/newline into the next embedded string.
_URL_RE = re.compile(rb"https?://[^\x00-\x20\"'<>]{3,}", re.IGNORECASE)
_IPV4_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Suspicious API / command tokens commonly seen in malware strings. Presence is a
# LEAD, not a verdict — benign software uses many of these too.
_SUSPICIOUS_APIS = [
    "VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "ReadProcessMemory",
    "CreateRemoteThread", "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
    "WinExec", "ShellExecute", "URLDownloadToFile", "InternetOpen", "WSASocket",
    "RegSetValue", "RegCreateKey", "SetWindowsHookEx", "NtUnmapViewOfSection",
    "CreateProcess", "IsDebuggerPresent", "cmd.exe", "powershell", "rundll32",
    "/bin/sh", "/bin/bash", "wget ", "curl ", "base64 -d", "chmod +x",
    "nc -e", "mimikatz", "ptrace",
]


def hash_file(path: str) -> dict:
    """Return md5/sha1/sha256 of the file, reading in chunks (never executing)."""
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


def detect_type(head: bytes) -> str:
    for sig, label in _MAGIC:
        if head.startswith(sig):
            return label
    # Fall back: all-printable small files are likely text/scripts.
    sample = head[:512]
    if sample and all(0x09 <= b <= 0x0D or 0x20 <= b <= 0x7E for b in sample):
        return "ASCII text / script"
    return "unknown / data"


def extract_strings(data: bytes, min_len: int = 4) -> list[str]:
    """Extract printable ASCII runs of at least min_len characters."""
    out: list[str] = []
    cur = bytearray()
    for b in data:
        if 0x20 <= b <= 0x7E:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii"))
            cur.clear()
    if len(cur) >= min_len:
        out.append(cur.decode("ascii"))
    return out


def heuristics(data: bytes, strings: list[str]) -> dict:
    """Flag embedded URLs/IPs (from raw bytes) and suspicious API/command tokens
    (from extracted strings, case-insensitive)."""
    urls = sorted({m.decode("ascii", "replace") for m in _URL_RE.findall(data)})
    ips = sorted({m.decode("ascii", "replace") for m in _IPV4_RE.findall(data)})
    joined = "\n".join(strings).lower()
    apis = sorted({a for a in _SUSPICIOUS_APIS if a.lower() in joined})
    return {"urls": urls, "ips": ips, "suspicious_apis": apis}


def triage(path: str, min_len: int = 4) -> dict:
    with open(path, "rb") as f:
        data = f.read()
    strings = extract_strings(data, min_len)
    flags = heuristics(data, strings)
    flag_total = len(flags["urls"]) + len(flags["ips"]) + len(flags["suspicious_apis"])
    return {
        "path": path,
        "size": len(data),
        "type": detect_type(data[:512]),
        **hash_file(path),
        "strings_count": len(strings),
        "flags": flags,
        "flagged": flag_total > 0,
        "strings": strings,
    }


def _print_report(r: dict, show_strings: bool) -> None:
    print(f"{r['path']}  ({r['size']} bytes)")
    print(f"  type   : {r['type']}")
    print(f"  md5    : {r['md5']}")
    print(f"  sha1   : {r['sha1']}")
    print(f"  sha256 : {r['sha256']}")
    print(f"  strings: {r['strings_count']} (min-len)")
    f = r["flags"]
    if r["flagged"]:
        if f["urls"]:
            print(f"  [!] URLs: {len(f['urls'])}  e.g. {f['urls'][0]}")
        if f["ips"]:
            print(f"  [!] IPs : {len(f['ips'])}  e.g. {f['ips'][0]}")
        if f["suspicious_apis"]:
            print(f"  [!] suspicious tokens: {', '.join(f['suspicious_apis'])}")
    else:
        print("  no URL/IP/suspicious-token heuristics matched (not proof of safety)")
    if show_strings:
        print("  --- strings ---")
        for s in r["strings"]:
            print(f"    {s}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Safe static file triage (no execution)")
    ap.add_argument("files", nargs="+", help="suspect files (read-only copies)")
    ap.add_argument("--min-len", type=int, default=4, help="minimum string length")
    ap.add_argument("--strings", action="store_true", help="dump extracted strings")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    results = []
    for p in args.files:
        try:
            results.append(triage(p, args.min_len))
        except OSError as e:
            print(f"error reading {p}: {e}", file=sys.stderr)
            return 3

    if args.json:
        if not args.strings:
            for r in results:
                r.pop("strings", None)
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            _print_report(r, args.strings)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
