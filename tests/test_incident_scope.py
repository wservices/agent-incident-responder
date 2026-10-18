"""Tests for incident_scope.py — NIST 800-61 scoring, pure functions, offline."""
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("incident_scope", ROOT / "scripts" / "incident_scope.py")
isc = importlib.util.module_from_spec(spec)
sys.modules["incident_scope"] = isc
spec.loader.exec_module(isc)


def test_score_maps_categories_to_ordinals():
    s = isc.score_incident("high", "integrity", "extended")
    assert s["functional_score"] == 3
    assert s["information_score"] == 3
    assert s["recoverability_score"] == 2
    assert s["total"] == 8


def test_not_recoverable_is_critical_even_with_low_impact():
    out = isc.classify(isc.score_incident("low", "none", "not_recoverable"))
    assert out["severity"] == "Critical" and out["priority"] == "P1"
    assert "recover" in out["rationale"].lower()


def test_high_functional_impact_is_high():
    out = isc.classify(isc.score_incident("high", "none", "regular"))
    assert out["severity"] == "High" and out["priority"] == "P2"


def test_integrity_loss_is_high():
    out = isc.classify(isc.score_incident("low", "integrity", "regular"))
    assert out["severity"] == "High"


def test_moderate_is_medium_and_minimal_is_low():
    assert isc.classify(isc.score_incident("low", "privacy", "regular"))["severity"] == "Medium"
    low = isc.classify(isc.score_incident("none", "none", "regular"))
    assert low["severity"] == "Low" and low["priority"] == "P4"


def test_input_normalization_accepts_hyphen_and_case():
    # "Not-Recoverable" / "HIGH" should normalize to the canonical keys.
    out = isc.assess("HIGH", "Proprietary", "Not-Recoverable")
    assert out["severity"] == "Critical"


def test_scope_summary_counts_assets_and_indicators():
    out = isc.assess("medium", "proprietary", "supplemented",
                     assets=["web01", "db02", "app03"],
                     indicators=["198.51.100.23", "deadbeef"])
    assert out["scope"]["asset_count"] == 3
    assert out["scope"]["indicator_count"] == 2
    assert out["severity"] == "High"  # total 2+2+1 = 5


def test_unknown_category_raises():
    with pytest.raises(ValueError):
        isc.score_incident("catastrophic", "none", "regular")


def test_load_incident_reads_yaml(tmp_path):
    pytest.importorskip("yaml")
    p = tmp_path / "incident.yaml"
    p.write_text(
        "incident:\n"
        "  functional_impact: high\n"
        "  information_impact: integrity\n"
        "  recoverability: extended\n"
        "  assets: [web01, db02]\n"
        "  indicators: ['198.51.100.23']\n")
    doc = isc.load_incident(str(p))
    out = isc.assess(doc["functional_impact"], doc["information_impact"],
                     doc["recoverability"], doc["assets"], doc["indicators"])
    assert out["severity"] == "Critical"  # total 3+3+2 = 8
    assert out["scope"]["asset_count"] == 2
