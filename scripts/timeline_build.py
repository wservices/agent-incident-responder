#!/usr/bin/env python3
"""Merge timestamped events from heterogeneous inputs into one super-timeline.

Reads one or more evidence files and fuses their events into a SINGLE
chronologically sorted timeline. Each output row keeps the source file it came
from as provenance, so a reviewer can trace any event back to its origin.

Supported line/file shapes (auto-detected per line, CSV by extension/flag):
  * syslog         : "Oct 15 10:01:02 web01 sshd[4411]: <message>"  (no year;
                     supply --year, defaults to the current UTC year)
  * ISO8601 line   : "2026-10-15T10:01:02Z <message>" / "2026-10-15 10:01:02 ..."
  * CSV            : a row with a timestamp column (auto-detected name or
                     --ts-column); the remaining columns become the message.

All timestamps are normalized to UTC for sorting and output. Timezone-aware ISO
values are converted to UTC; naive values (syslog, bare ISO) are assumed UTC and
the assumption is noted on the row. Read-only; input is untrusted DATA — event
text is never executed.

Usage:
  timeline_build.py auth.log app.csv events.iso --json
  timeline_build.py --year 2026 --csv-out auth.log syslog
  timeline_build.py --ts-column when app.csv

Exit: 0 if any events parsed, 1 if none, 3 usage error.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import io
import json
import os
import sys

import re

_SYSLOG_RE = re.compile(
    r"^(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<rest>.*)$"
)
_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}

# Leading ISO8601 timestamp of a generic "<ts> <message>" line.
_ISO_LEAD_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    r"[\sT]+(?P<rest>.*)$"
)

_TS_COLUMN_CANDIDATES = ("timestamp", "time", "datetime", "date", "@timestamp", "when")


def parse_iso(value: str):
    """Parse an ISO8601 string to a naive UTC datetime, or None.

    Accepts 'T' or space separators, optional fractional seconds, a trailing 'Z',
    or a numeric offset. Offsets are converted to UTC; the returned datetime is
    tz-naive (UTC) so all events sort against one scale.
    """
    s = value.strip().replace(" ", "T", 1)
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    # Normalize "+0000" to "+00:00" for fromisoformat on older interpreters.
    m = re.search(r"([+-]\d{2})(\d{2})$", s)
    if m:
        s = s[: m.start()] + m.group(1) + ":" + m.group(2)
    try:
        parsed = dt.datetime.fromisoformat(s)
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(dt.timezone.utc).replace(tzinfo=None)
    return parsed


def parse_syslog(line: str, year: int):
    """Parse a BSD-syslog line to (naive UTC datetime, message) or None."""
    m = _SYSLOG_RE.match(line)
    if not m:
        return None
    hh, mm, ss = (int(x) for x in m.group("time").split(":"))
    try:
        when = dt.datetime(year, _MONTHS[m.group("mon")], int(m.group("day")),
                           hh, mm, ss)
    except ValueError:
        return None
    return when, m.group("rest").strip()


def parse_generic(line: str):
    """Parse a '<ISO8601> <message>' line to (naive UTC datetime, message)."""
    m = _ISO_LEAD_RE.match(line)
    if not m:
        return None
    when = parse_iso(m.group("ts"))
    if when is None:
        return None
    return when, m.group("rest").strip()


def _detect_ts_column(fieldnames) -> str | None:
    lowered = {(f or "").strip().lower(): f for f in (fieldnames or [])}
    for cand in _TS_COLUMN_CANDIDATES:
        if cand in lowered:
            return lowered[cand]
    return None


def parse_csv(text: str, source: str, ts_column: str | None = None) -> list[dict]:
    """Parse CSV text into events. The timestamp column is auto-detected unless
    ts_column is given; remaining columns become 'k=v' message fields."""
    events: list[dict] = []
    reader = csv.DictReader(io.StringIO(text))
    col = ts_column or _detect_ts_column(reader.fieldnames)
    if not col:
        return events
    for row in reader:
        when = parse_iso(str(row.get(col, "")))
        if when is None:
            continue
        parts = [f"{k}={v}" for k, v in row.items() if k != col and v not in (None, "")]
        events.append(_event(when, source, "csv", ", ".join(parts)))
    return events


def _event(when: dt.datetime, source: str, kind: str, message: str) -> dict:
    return {
        "timestamp": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "_sort": when,
        "source": source,
        "kind": kind,
        "message": message,
    }


def parse_text_lines(text: str, source: str, year: int) -> list[dict]:
    """Parse a text file line by line, trying ISO-leading then syslog shapes."""
    events: list[dict] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        g = parse_generic(line)
        if g:
            events.append(_event(g[0], source, "iso", g[1]))
            continue
        s = parse_syslog(line, year)
        if s:
            events.append(_event(s[0], source, "syslog", s[1]))
    return events


def parse_file(path: str, year: int, ts_column: str | None = None,
               force_csv: bool = False) -> list[dict]:
    with open(path, encoding="utf-8-sig", errors="replace") as f:
        text = f.read()
    if force_csv or path.lower().endswith(".csv"):
        return parse_csv(text, path, ts_column)
    return parse_text_lines(text, path, year)


def build_timeline(files, year: int, ts_column: str | None = None,
                   force_csv: bool = False) -> list[dict]:
    events: list[dict] = []
    for path in files:
        events.extend(parse_file(path, year, ts_column, force_csv))
    # Stable, deterministic ordering: time, then source, then message.
    events.sort(key=lambda e: (e["_sort"], e["source"], e["message"]))
    return events


def _public_rows(events):
    return [{k: v for k, v in e.items() if k != "_sort"} for e in events]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Merge events into one super-timeline")
    ap.add_argument("files", nargs="+", help="evidence files to merge")
    ap.add_argument("--year", type=int, default=dt.datetime.now(dt.timezone.utc).year,
                    help="year to assume for syslog lines (no year in format)")
    ap.add_argument("--ts-column", help="CSV timestamp column (else auto-detected)")
    ap.add_argument("--csv-input", action="store_true",
                    help="treat all inputs as CSV regardless of extension")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--csv-out", action="store_true", help="CSV output")
    args = ap.parse_args(argv)

    try:
        events = build_timeline(args.files, args.year, args.ts_column, args.csv_input)
    except OSError as e:
        print(f"error reading input: {e}", file=sys.stderr)
        return 3

    rows = _public_rows(events)
    if args.json:
        print(json.dumps(rows, indent=2))
    elif args.csv_out:
        w = csv.writer(sys.stdout)
        w.writerow(["timestamp", "source", "kind", "message"])
        for r in rows:
            w.writerow([r["timestamp"], os.path.basename(r["source"]), r["kind"],
                        r["message"]])
    else:
        print(f"Super-timeline: {len(rows)} event(s) from {len(args.files)} source(s)")
        for r in rows:
            print(f"  {r['timestamp']}  [{r['kind']}:{os.path.basename(r['source'])}]  "
                  f"{r['message']}")
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
