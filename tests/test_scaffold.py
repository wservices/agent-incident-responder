"""Offline scaffold smoke test for the incident-responder role.

Validates the profile manifest and every bundled SKILL.md without any network,
secrets, or live tooling. Pure stdlib + PyYAML (available in CI).

Run:  python3 -m pytest tests -q
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
SKILLS_DIR = REPO / "skills"

SEMVER = re.compile(r"^\d+\.\d+\.\d+$")
VALID_PLATFORMS = {"linux", "macos", "windows"}

# Body section headings, in the exact required order.
REQUIRED_SECTIONS = [
    "## When to Use",
    "## Prerequisites",
    "## How to Run",
    "## Quick Reference",
    "## Procedure",
    "## Pitfalls",
    "## Verification",
]

REQUIRED_DIST_FIELDS = [
    "name",
    "version",
    "description",
    "hermes_requires",
    "author",
    "license",
]


def _split_frontmatter(text: str):
    """Return (frontmatter_dict, body_str) for a `---`-delimited Markdown file."""
    assert text.startswith("---"), "SKILL.md must start with YAML frontmatter"
    parts = text.split("---", 2)
    assert len(parts) == 3, "SKILL.md needs opening and closing '---' fences"
    fm = yaml.safe_load(parts[1]) or {}
    return fm, parts[2]


def skill_files():
    return sorted(SKILLS_DIR.glob("*/SKILL.md"))


# --- distribution.yaml ------------------------------------------------------

def test_distribution_parses_and_has_required_fields():
    dist = REPO / "distribution.yaml"
    assert dist.exists(), "distribution.yaml is missing"
    data = yaml.safe_load(dist.read_text(encoding="utf-8"))
    assert isinstance(data, dict), "distribution.yaml must parse to a mapping"
    for field in REQUIRED_DIST_FIELDS:
        assert data.get(field), f"distribution.yaml missing field: {field}"
    assert data["name"] == "incident-responder"
    assert SEMVER.match(str(data["version"])), "version must be semver x.y.z"
    # env_requires, when present, must be a list of named entries, all optional.
    env = data.get("env_requires") or []
    assert isinstance(env, list) and env, "env_requires should be a non-empty list"
    for e in env:
        assert e.get("name"), "each env_requires entry needs a name"
        assert e.get("required") is False, f"{e.get('name')} must be required: false"


def test_distribution_owned_includes_core():
    data = yaml.safe_load((REPO / "distribution.yaml").read_text(encoding="utf-8"))
    owned = set(data.get("distribution_owned") or [])
    for item in ("SOUL.md", "skills", "distribution.yaml"):
        assert item in owned, f"distribution_owned should include {item}"


# --- skills -----------------------------------------------------------------

def test_skills_exist():
    files = skill_files()
    assert len(files) == 7, f"expected 7 skills, found {len(files)}"


@pytest.mark.parametrize("skill_path", skill_files(), ids=lambda p: p.parent.name)
def test_skill_frontmatter_valid(skill_path: Path):
    fm, _ = _split_frontmatter(skill_path.read_text(encoding="utf-8"))
    name = fm.get("name")
    assert name, "frontmatter needs a name"
    assert name == skill_path.parent.name, "name must match the skill directory"

    desc = fm.get("description", "")
    assert isinstance(desc, str) and desc, "description required"
    assert len(desc) <= 60, f"description >60 chars ({len(desc)}): {desc!r}"
    assert desc.endswith("."), "description must end with a period"

    assert SEMVER.match(str(fm.get("version", ""))), "version must be semver x.y.z"
    assert fm.get("author"), "author required"
    assert fm.get("license"), "license required"

    platforms = fm.get("platforms") or []
    assert platforms, "platforms required"
    assert set(platforms) <= VALID_PLATFORMS, f"invalid platforms: {platforms}"

    hermes = (fm.get("metadata") or {}).get("hermes") or {}
    assert isinstance(hermes.get("tags"), list) and hermes["tags"], "metadata.hermes.tags required"
    assert "related_skills" in hermes, "metadata.hermes.related_skills required"


@pytest.mark.parametrize("skill_path", skill_files(), ids=lambda p: p.parent.name)
def test_skill_sections_present_and_ordered(skill_path: Path):
    _, body = _split_frontmatter(skill_path.read_text(encoding="utf-8"))
    positions = []
    for heading in REQUIRED_SECTIONS:
        idx = body.find("\n" + heading)
        assert idx != -1, f"{skill_path.parent.name} missing section: {heading}"
        positions.append(idx)
    assert positions == sorted(positions), (
        f"{skill_path.parent.name} sections out of order; expected {REQUIRED_SECTIONS}"
    )
