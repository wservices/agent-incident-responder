"""Tests for static_triage.py — reads bytes only, never executes. Offline."""
import hashlib
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("static_triage", ROOT / "scripts" / "static_triage.py")
st = importlib.util.module_from_spec(spec)
sys.modules["static_triage"] = st
spec.loader.exec_module(st)

# Synthetic "sample": ELF magic + suspicious API/URL/IP strings. NOT a real binary.
SAMPLE_BYTES = (
    b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    + b"VirtualAlloc\x00WriteProcessMemory\x00"
    + b"http://malware.evil.example/payload.bin\x00"
    + b"connect 198.51.100.23\x00/bin/sh -c id\x00"
    + b"\x01\x02harmless padding here\x00"
)


def test_hashes_match_hashlib(tmp_path):
    p = tmp_path / "suspect.sample"
    p.write_bytes(SAMPLE_BYTES)
    r = st.triage(str(p))
    assert r["md5"] == hashlib.md5(SAMPLE_BYTES).hexdigest()
    assert r["sha1"] == hashlib.sha1(SAMPLE_BYTES).hexdigest()
    assert r["sha256"] == hashlib.sha256(SAMPLE_BYTES).hexdigest()
    assert r["size"] == len(SAMPLE_BYTES)


def test_type_detection_by_magic_bytes():
    assert st.detect_type(b"\x7fELF....") == "ELF executable"
    assert st.detect_type(b"MZ\x90\x00") == "PE/DOS executable (MZ)"
    assert st.detect_type(b"%PDF-1.7") == "PDF document"
    assert st.detect_type(b"PK\x03\x04") == "ZIP/Office archive"
    assert st.detect_type(b"#!/bin/sh\n") == "script (shebang)"
    assert st.detect_type(b"plain readable text") == "ASCII text / script"
    assert st.detect_type(b"\x00\x01\x02\xff") == "unknown / data"


def test_strings_respects_min_len():
    data = b"ab\x00abcdef\x00xy\x00longenoughstring"
    short = st.extract_strings(data, min_len=4)
    assert "abcdef" in short and "longenoughstring" in short
    assert "ab" not in short and "xy" not in short
    long_only = st.extract_strings(data, min_len=10)
    assert long_only == ["longenoughstring"]


def test_heuristics_flag_url_ip_and_suspicious_apis():
    strings = st.extract_strings(SAMPLE_BYTES, min_len=4)
    flags = st.heuristics(SAMPLE_BYTES, strings)
    assert flags["urls"] == ["http://malware.evil.example/payload.bin"]  # no NUL bleed
    assert "198.51.100.23" in flags["ips"]
    assert "VirtualAlloc" in flags["suspicious_apis"]
    assert "WriteProcessMemory" in flags["suspicious_apis"]
    assert "/bin/sh" in flags["suspicious_apis"]


def test_clean_file_not_flagged(tmp_path):
    p = tmp_path / "readme.txt"
    p.write_bytes(b"This is a perfectly ordinary text file with no indicators.\n")
    r = st.triage(str(p))
    assert r["flagged"] is False
    assert r["flags"] == {"urls": [], "ips": [], "suspicious_apis": []}


def test_triage_does_not_require_execute_bit(tmp_path):
    # The sample is read as bytes; triage must work regardless of mode / no exec.
    p = tmp_path / "noexec.sample"
    p.write_bytes(SAMPLE_BYTES)
    p.chmod(0o600)
    r = st.triage(str(p))
    assert r["type"] == "ELF executable" and r["flagged"] is True
