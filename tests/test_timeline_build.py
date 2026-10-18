"""Tests for timeline_build.py — pure parsing/merging, no network."""
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("timeline_build", ROOT / "scripts" / "timeline_build.py")
tb = importlib.util.module_from_spec(spec)
sys.modules["timeline_build"] = tb
spec.loader.exec_module(tb)


def test_parse_iso_handles_z_space_and_offset():
    assert tb.parse_iso("2026-10-15T10:01:02Z").strftime("%H:%M:%S") == "10:01:02"
    assert tb.parse_iso("2026-10-15 10:01:02").strftime("%H:%M:%S") == "10:01:02"
    # +02:00 offset normalizes to 08:01:02 UTC
    assert tb.parse_iso("2026-10-15T10:01:02+02:00").strftime("%H:%M:%S") == "08:01:02"
    assert tb.parse_iso("not-a-time") is None


def test_parse_syslog_uses_supplied_year():
    when, msg = tb.parse_syslog(
        "Oct 15 10:01:02 web01 sshd[4411]: Failed password for deploy", year=2026)
    assert when.year == 2026 and when.month == 10 and when.day == 15
    assert when.strftime("%H:%M:%S") == "10:01:02"
    assert "Failed password for deploy" in msg
    assert tb.parse_syslog("not a syslog line", year=2026) is None


def test_parse_generic_iso_line():
    when, msg = tb.parse_generic("2026-10-15T10:03:30Z firewall outbound beacon")
    assert when.strftime("%H:%M:%S") == "10:03:30"
    assert msg == "firewall outbound beacon"
    assert tb.parse_generic("plain line no timestamp") is None


def test_parse_csv_autodetects_timestamp_column(tmp_path):
    p = tmp_path / "app.csv"
    p.write_text("timestamp,host,action\n2026-10-15T10:02:15Z,db02,login\n")
    events = tb.parse_csv(p.read_text(), str(p))
    assert len(events) == 1
    assert events[0]["kind"] == "csv"
    assert events[0]["timestamp"] == "2026-10-15T10:02:15Z"
    assert "host=db02" in events[0]["message"] and "action=login" in events[0]["message"]


def test_csv_explicit_column_overrides_autodetect(tmp_path):
    p = tmp_path / "x.csv"
    p.write_text("when,note\n2026-10-15T09:00:00Z,boot\n")
    events = tb.parse_csv(p.read_text(), str(p), ts_column="when")
    assert len(events) == 1 and events[0]["timestamp"] == "2026-10-15T09:00:00Z"


def test_build_timeline_merges_sorts_and_keeps_provenance(tmp_path):
    (tmp_path / "auth.log").write_text(
        "Oct 15 10:05:00 web01 sshd[1]: Accepted password for deploy\n"
        "Oct 15 10:01:02 web01 sshd[1]: Failed password for deploy\n")
    (tmp_path / "events.iso").write_text("2026-10-15T10:03:30Z firewall beacon\n")
    (tmp_path / "app.csv").write_text(
        "timestamp,host\n2026-10-15T10:06:45+02:00,db02\n")  # -> 08:06:45Z, earliest

    events = tb.build_timeline(
        [str(tmp_path / "auth.log"), str(tmp_path / "events.iso"), str(tmp_path / "app.csv")],
        year=2026)
    stamps = [e["timestamp"] for e in events]
    assert stamps == sorted(stamps)                      # chronological
    assert stamps[0] == "2026-10-15T08:06:45Z"           # offset normalized to UTC first
    # every row carries its source file as provenance
    sources = {Path(e["source"]).name for e in events}
    assert sources == {"auth.log", "events.iso", "app.csv"}
    kinds = {e["kind"] for e in events}
    assert kinds == {"syslog", "iso", "csv"}


def test_unparseable_lines_are_skipped(tmp_path):
    (tmp_path / "noise.log").write_text("garbage\n\n2026-10-15T10:00:00Z real event\n")
    events = tb.build_timeline([str(tmp_path / "noise.log")], year=2026)
    assert len(events) == 1 and events[0]["message"] == "real event"
