"""Tests for ioc_extract.py — pure functions, no network."""
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("ioc_extract", ROOT / "scripts" / "ioc_extract.py")
ioc = importlib.util.module_from_spec(spec)
sys.modules["ioc_extract"] = ioc
spec.loader.exec_module(ioc)

SAMPLE = """
Oct 15 10:01:02 web01 sshd[4411]: Failed password for invalid user deploy from 198.51.100.23 port 51234 ssh2
Internal host 10.0.4.11 beaconed to http://malware.evil.example/payload.bin
Contact phish@bad-domain.test for the key. Hash: 44d88612fea8a8f36de82e1278abb02f
SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
IPv6 beacon 2001:0db8:0000:0000:0000:0000:0000:0001
"""


def test_extracts_public_ip_and_drops_private_when_public_only():
    all_iocs = ioc.extract(SAMPLE)
    assert "198.51.100.23" in all_iocs["ipv4"]
    assert "10.0.4.11" in all_iocs["ipv4"]
    pub = ioc.extract(SAMPLE, public_only=True)
    assert "198.51.100.23" in pub["ipv4"]
    assert "10.0.4.11" not in pub["ipv4"]  # private dropped


def test_extracts_url_domain_email_hashes():
    out = ioc.extract(SAMPLE)
    assert "http://malware.evil.example/payload.bin" in out["url"]
    assert "malware.evil.example" in out["domain"]
    assert "phish@bad-domain.test" in out["email"]
    assert "44d88612fea8a8f36de82e1278abb02f" in out["md5"]
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in out["sha256"]


def test_syslog_time_not_mistaken_for_ipv6_but_real_ipv6_kept():
    out = ioc.extract(SAMPLE)
    # "10:01:02" (a syslog time) matches the loose regex but is not a valid IPv6.
    assert "10:01:02" not in out["ipv6"]
    assert "2001:0db8:0000:0000:0000:0000:0000:0001" in out["ipv6"]


def test_email_host_not_also_listed_as_domain():
    out = ioc.extract("mail to phish@bad-domain.test only")
    assert "bad-domain.test" not in out["domain"]
    assert "phish@bad-domain.test" in out["email"]


def test_defang_on_by_default():
    out = ioc.apply_defang(ioc.extract(SAMPLE), enabled=True)
    assert "198[.]51[.]100[.]23" in out["ipv4"]
    assert any(u.startswith("hxxp://") for u in out["url"])
    assert all("[.]" in d for d in out["domain"])
    assert all("[at]" in e for e in out["email"])
    # hashes are safe raw and must not be defanged
    assert "44d88612fea8a8f36de82e1278abb02f" in out["md5"]


def test_no_defang_option_leaves_raw():
    raw = ioc.apply_defang(ioc.extract(SAMPLE), enabled=False)
    assert "198.51.100.23" in raw["ipv4"]
    assert "http://malware.evil.example/payload.bin" in raw["url"]


def test_cli_defang_and_no_defang_are_mutually_exclusive(capsys):
    rc = ioc.main(["--defang", "--no-defang"])
    assert rc == 3


def test_filenames_not_flagged_as_domains():
    out = ioc.extract("opened auth.log and config.json and run.sh")
    assert out["domain"] == []
