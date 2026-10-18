---
name: incident-reporting
description: NIST incident report and a validated handoff.
version: 0.1.0
author: Pascal (pascal), Hermes Agent
license: MIT
platforms: [linux]
prerequisites:
  commands: [python3, jq]
metadata:
  hermes:
    tags: [reporting, nist-800-61, handoff, evidence, incident-response]
    related_skills: [incident-triage-and-scoping, containment-and-recovery-planning, ioc-extraction-and-enrichment]
---

# Incident Reporting Skill

Assemble the incident's triage, timeline, findings, IOCs, ATT&CK mapping, and
proposed containment/eradication/recovery into a NIST SP 800-61r2-style incident
report, plus a machine-readable `handoff.yaml` for the next agent or the Security
Team Lead. Enforces observation-vs-assumption labeling, evidence references on
every claim, and defanged indicators throughout.

## When to Use

- Closing out or escalating a confirmed incident.
- Producing the artifact the Security Team Lead / Digital Forensics Analyst consumes.
- Packaging proposed response actions with their required approvals.
- **Don't use for:** the SOC analyst's first-line investigation report
  (`security-analyst` owns that) — this is the incident-lifecycle report.

## Prerequisites

- The case dir populated: `case.yaml` (triage), `timeline/`, `iocs/`,
  `response-plan.md`, and hashed `evidence/`.
- `templates/report.md` and `templates/handoff.yaml` (in this skill), and
  `agents/platform/policies/HANDOFF-FORMAT.md`. `python3` + `jq` to validate.

## How to Run

Fill `templates/report.md` into `cases/<id>/report.md`, emit `handoff.yaml` from
`templates/handoff.yaml`, then validate the handoff structure:

`terminal(command="python3 -c \"import yaml; h=yaml.safe_load(open('cases/INC-2026-0007/handoff.yaml'))['handoff']; req=['task_id','originating_agent','receiving_agent','created_at','summary','findings','status']; m=[k for k in req if k not in h]; assert not m, 'missing: '+','.join(m); assert all('confidence' in f and 'basis' in f for f in h['findings']), 'finding needs confidence+basis'; print('handoff OK')\"", timeout=30)`

## Quick Reference

```
cp skills/incident-reporting/templates/report.md   cases/INC-2026-0007/report.md
cp skills/incident-reporting/templates/handoff.yaml cases/INC-2026-0007/handoff.yaml
# validate the handoff is well-formed YAML and complete
python3 -c "import yaml;yaml.safe_load(open('cases/INC-2026-0007/handoff.yaml'))"
# optional: render the report to PDF (companion skill markdown-to-pdf)
pandoc cases/INC-2026-0007/report.md -o report.pdf --pdf-engine=wkhtmltopdf
```

## Procedure

1. **Executive summary.** What happened, affected assets, severity, current
   status, disposition. Completion: readable without the appendices.
2. **Timeline (UTC).** Ordered events from `forensic-timeline-reconstruction` /
   `siem-alert-correlation`, each citing an evidence row. Completion: every row has
   a UTC timestamp and an evidence ref.
3. **Findings.** Each labeled `observed | inferred | assumed` with a confidence and
   evidence refs (Security Policy rule 9). Completion: no unlabeled claims.
4. **Indicators.** Defanged IOC table with dispositions + enrichment sources.
   Completion: matches `iocs/` output; all defanged.
5. **ATT&CK mapping.** Technique ids with the evidence supporting each. Completion:
   every mapping justified, not guessed.
6. **Response actions.** Proposed containment/eradication/recovery from the plan,
   each with owner + required approval, clearly marked *proposed, not executed*.
   Completion: no action attributed to the agent as done.
7. **Handoff.** Emit `handoff.yaml` per `HANDOFF-FORMAT.md`; set `receiving_agent`
   (Security Team Lead for major incidents) and `required_approval`. Completion:
   the validation command prints `handoff OK`.

## Pitfalls

- **Claiming execution.** The role proposes; the report must never state a
  containment step was performed by the agent.
- **Unlabeled assumptions / missing evidence refs.** Every claim states basis and
  confidence and points to reproducible evidence.
- **Refanged indicators.** Keep IOCs defanged in all human-readable text; raw form
  only in the structured handoff `value` field.
- **Broken `task_id` chain.** Reuse the id from the inbound handoff; never mint a
  new one mid-incident.

## Verification

- The `How to Run` validation prints `handoff OK` (required fields present; every
  finding has `confidence` + `basis`).
- `python3 -c "import yaml;yaml.safe_load(open('cases/<id>/handoff.yaml'))"` exits 0
  (well-formed YAML).
- A reviewer can reproduce every finding from its evidence reference alone, and the
  report contains: summary, UTC timeline, labeled findings, defanged IOCs, justified
  ATT&CK mapping, and clearly-proposed response actions.
