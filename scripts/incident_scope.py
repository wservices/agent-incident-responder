#!/usr/bin/env python3
"""NIST SP 800-61r2 incident severity + scoping calculator.

Combines the three NIST "Detection & Analysis" prioritization categories —
Functional Impact, Information Impact, and Recoverability Effort — into a single
severity label (Low/Medium/High/Critical), a priority (P1-P4), and a short
rationale. It also summarizes scope: the count of affected assets and indicators.

Inputs come from CLI flags, an incident YAML, or both (CLI flags override YAML).
This is advisory scoping only: it recommends a severity from the inputs, takes no
response action, and treats the incident file as untrusted DATA (never executes
field contents).

Usage:
  incident_scope.py --functional-impact high --information-impact integrity \\
                    --recoverability extended
  incident_scope.py --incident cases/INC-2026-0007/incident.yaml --json

Incident YAML (all optional):
  functional_impact: high        # none|low|medium|high
  information_impact: integrity   # none|privacy|proprietary|integrity
  recoverability: extended        # regular|supplemented|extended|not_recoverable
  assets: [web01, db02]
  indicators: ["198.51.100.23", "<sha256>"]

Exit: 0 on success, 3 usage/parse error.
"""
from __future__ import annotations

import argparse
import json
import sys

# NIST SP 800-61r2 Tables 3-2/3-3/3-4 categories → ordinal scores (0 = none).
FUNCTIONAL = {"none": 0, "low": 1, "medium": 2, "high": 3}
INFORMATION = {"none": 0, "privacy": 1, "proprietary": 2, "integrity": 3}
RECOVERABILITY = {"regular": 0, "supplemented": 1, "extended": 2, "not_recoverable": 3}

# Priority label per severity.
_PRIORITY = {"Low": "P4", "Medium": "P3", "High": "P2", "Critical": "P1"}


def _norm(value: str) -> str:
    return str(value).strip().lower().replace("-", "_").replace(" ", "_")


def score_incident(functional: str, information: str, recoverability: str) -> dict:
    """Map the three category inputs to ordinal scores. Raises ValueError on an
    unknown category value."""
    fn, inf, rec = _norm(functional), _norm(information), _norm(recoverability)
    if fn not in FUNCTIONAL:
        raise ValueError(f"functional_impact '{functional}' not in {sorted(FUNCTIONAL)}")
    if inf not in INFORMATION:
        raise ValueError(f"information_impact '{information}' not in {sorted(INFORMATION)}")
    if rec not in RECOVERABILITY:
        raise ValueError(f"recoverability '{recoverability}' not in {sorted(RECOVERABILITY)}")
    f, i, r = FUNCTIONAL[fn], INFORMATION[inf], RECOVERABILITY[rec]
    return {
        "functional_impact": fn, "functional_score": f,
        "information_impact": inf, "information_score": i,
        "recoverability": rec, "recoverability_score": r,
        "total": f + i + r,
    }


def classify(scores: dict) -> dict:
    """Derive a severity label + priority + rationale from category scores.

    Rules (deterministic):
      * not_recoverable, OR total >= 7                          -> Critical
      * high functional impact, OR integrity loss, OR total >=5 -> High
      * total >= 2                                              -> Medium
      * total == 0                                              -> Low (minimal)
      * otherwise                                               -> Low
    """
    f = scores["functional_score"]
    i = scores["information_score"]
    r = scores["recoverability_score"]
    total = scores["total"]

    reasons: list[str] = []
    if r == RECOVERABILITY["not_recoverable"]:
        severity = "Critical"
        reasons.append("recovery not possible without external resources")
    elif total >= 7:
        severity = "Critical"
        reasons.append(f"combined impact score {total} is severe")
    elif f == FUNCTIONAL["high"]:
        severity = "High"
        reasons.append("high functional impact to mission-critical services")
    elif i == INFORMATION["integrity"]:
        severity = "High"
        reasons.append("integrity loss / exfiltration of sensitive data")
    elif total >= 5:
        severity = "High"
        reasons.append(f"combined impact score {total}")
    elif total >= 2:
        severity = "Medium"
        reasons.append(f"moderate combined impact (score {total})")
    else:
        severity = "Low"
        reasons.append("minimal impact" if total == 0 else f"limited impact (score {total})")

    return {
        "severity": severity,
        "priority": _PRIORITY[severity],
        "rationale": "; ".join(reasons),
    }


def summarize_scope(assets, indicators) -> dict:
    assets = list(assets or [])
    indicators = list(indicators or [])
    return {
        "asset_count": len(assets),
        "indicator_count": len(indicators),
        "assets": assets,
        "indicators": indicators,
    }


def assess(functional: str, information: str, recoverability: str,
           assets=None, indicators=None) -> dict:
    scores = score_incident(functional, information, recoverability)
    out = classify(scores)
    out["scores"] = scores
    out["scope"] = summarize_scope(assets, indicators)
    return out


def load_incident(path: str) -> dict:
    with open(path, encoding="utf-8-sig") as f:
        text = f.read()
    try:
        import yaml  # type: ignore
    except ImportError:
        raise SystemExit(
            "incident_scope requires PyYAML to read an incident file "
            "(pip install pyyaml / apt install python3-yaml)"
        )
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError("incident file is not a mapping")
    return data.get("incident", data)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="NIST 800-61 incident severity + scoping")
    ap.add_argument("--incident", help="incident YAML with impacts/assets/indicators")
    ap.add_argument("--functional-impact", help="none|low|medium|high")
    ap.add_argument("--information-impact", help="none|privacy|proprietary|integrity")
    ap.add_argument("--recoverability", help="regular|supplemented|extended|not_recoverable")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    doc: dict = {}
    if args.incident:
        try:
            doc = load_incident(args.incident)
        except (OSError, ValueError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 3

    functional = args.functional_impact or doc.get("functional_impact")
    information = args.information_impact or doc.get("information_impact")
    recoverability = args.recoverability or doc.get("recoverability")
    if not (functional and information and recoverability):
        print("error: functional-impact, information-impact and recoverability are "
              "all required (via flags or incident YAML)", file=sys.stderr)
        return 3

    try:
        result = assess(functional, information, recoverability,
                        doc.get("assets"), doc.get("indicators"))
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 3

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        s = result["scope"]
        print(f"Severity: {result['severity']} ({result['priority']})")
        print(f"Rationale: {result['rationale']}")
        print(f"Scope: {s['asset_count']} asset(s), {s['indicator_count']} indicator(s)")
        if s["assets"]:
            print(f"  assets    : {', '.join(map(str, s['assets']))}")
        if s["indicators"]:
            print(f"  indicators: {len(s['indicators'])} recorded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
