"""Tests for validate_handoff.py — requires PyYAML (present in test venv/CI)."""
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("vh", ROOT / "scripts" / "validate_handoff.py")
vh = importlib.util.module_from_spec(spec)
sys.modules["vh"] = vh
spec.loader.exec_module(vh)

pytest.importorskip("yaml")

GOOD = {
    "handoff": {
        "task_id": "INC-2026-0007",
        "originating_agent": "incident-responder",
        "receiving_agent": "security-team-lead",
        "created_at": "2026-10-16T14:05:00Z",
        "summary": "Confirmed intrusion on web01; containment proposed",
        "status": "in-progress",
        "required_approval": "human-approval",
        "findings": [
            {"id": "F1", "confidence": "high", "basis": "observed",
             "evidence_refs": ["evidence/suspect.sample.sha256"]}
        ],
        "indicators": [
            {"type": "ipv4", "value": "198.51.100.23", "disposition": "suspicious"}
        ],
    }
}


def test_good_handoff_valid():
    assert vh.validate(GOOD) == []


def test_missing_required_summary_and_findings():
    bad = {"handoff": dict(GOOD["handoff"])}
    del bad["handoff"]["summary"]
    del bad["handoff"]["findings"]
    errs = vh.validate(bad)
    assert any("summary" in e for e in errs)
    assert any("findings" in e for e in errs)


def test_bad_status():
    bad = {"handoff": dict(GOOD["handoff"], status="pending")}
    assert any("status" in e for e in vh.validate(bad))


def test_bad_approval():
    bad = {"handoff": dict(GOOD["handoff"], required_approval="maybe")}
    assert any("required_approval" in e for e in vh.validate(bad))


def test_finding_missing_confidence_and_evidence():
    bad = {"handoff": dict(GOOD["handoff"],
                           findings=[{"id": "F1", "basis": "observed"}])}
    errs = vh.validate(bad)
    assert any("confidence" in e for e in errs)
    assert any("evidence_refs" in e for e in errs)


def test_bad_indicator_disposition():
    bad = {"handoff": dict(GOOD["handoff"],
                           indicators=[{"type": "ipv4", "value": "198.51.100.23",
                                        "disposition": "scary"}])}
    assert any("disposition" in e for e in vh.validate(bad))


def test_repo_template_handoff_is_valid():
    import yaml
    doc = yaml.safe_load(
        (ROOT / "skills" / "incident-reporting" / "templates" / "handoff.yaml").read_text())
    assert vh.validate(doc) == []
