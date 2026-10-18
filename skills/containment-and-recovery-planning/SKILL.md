---
name: containment-and-recovery-planning
description: Propose containment and recovery steps, never run.
version: 0.1.0
author: Pascal (pascal), Hermes Agent
license: MIT
platforms: [linux]
prerequisites:
  commands: [python3]
metadata:
  hermes:
    tags: [containment, eradication, recovery, nist-800-61, advisory]
    related_skills: [incident-triage-and-scoping, siem-alert-correlation, incident-reporting]
---

# Containment and Recovery Planning Skill

Turn the confirmed incident's evidence into a concrete, prioritized plan for
containment, eradication, and recovery (NIST SP 800-61r2). This skill is strictly
**advisory**: it writes a plan a human reviews and executes. It never isolates a
host, blocks an IP, kills a process, changes a firewall/rule, or touches
production — every step is a proposal with an owner, a prerequisite approval, and
a rollback.

## When to Use

- Scoping and triage are done and you can justify response options with evidence.
- You need short-term containment plus eradication and recovery sequencing.
- Preparing the action plan the Security Team Lead / operator will approve and run.
- **Don't use for:** executing any step yourself (never), or planning beyond the
  evidence (don't invent affected systems).

## Prerequisites

- A scoped incident: affected assets, IOCs, timeline, and ATT&CK mapping from the
  earlier skills. `python3` (stdlib) to render/validate the plan.
- No credentials with write/response scope are used by this role; any executing
  account belongs to the human operator, not the agent (Security Policy §§2, 4).

## How to Run

Draft the plan from the case evidence into `cases/<id>/response-plan.md`, then
sanity-check its structure:

`terminal(command="python3 -c \"import sys,re; t=open('cases/INC-2026-0007/response-plan.md').read(); [sys.exit('missing '+s) for s in ['Containment','Eradication','Recovery','Approval'] if s not in t]; print('plan sections present')\"", timeout=30)`

## Quick Reference

```
# NIST phases to cover, in order
Short-term containment   # stop the bleeding (reversible, least business impact)
Evidence preservation    # image/snapshot before any eradication
Eradication              # remove persistence, accounts, artifacts
Recovery                 # restore from known-good, monitor, validate
# every step records: action | owner | prerequisite approval | rollback | verification
```

## Procedure

1. **Short-term containment options.** For each affected asset propose the
   least-impact reversible step (host isolation, account disable, IP block at the
   edge), with business-impact and tradeoffs. Completion: each option tagged
   reversible/irreversible with impact noted.
2. **Require evidence preservation first.** Mandate a forensic image/snapshot and
   hash before any eradication. Completion: a "preserve before eradicate" gate in
   the plan.
3. **Eradication steps.** Remove persistence (services, cron, run keys), rotate
   compromised credentials, delete artifacts — each tied to a timeline/IOC finding.
   Completion: every eradication step cites the evidence that justifies it.
4. **Recovery & validation.** Restore from known-good, rebuild vs. clean decision,
   monitoring to confirm the threat is gone, and return-to-service criteria.
   Completion: measurable recovery exit criteria defined.
5. **Approvals & ownership.** Mark each step `required_approval` (human-approval
   for anything production-impacting) and a human owner; nothing is auto-executed.
   Completion: no step is attributed to the agent for execution.

## Pitfalls

- **Never execute.** This role proposes; a human runs it. Do not call any tool
  that would isolate, block, kill, or reconfigure (Security Policy rules 2/4).
- **Containment vs. evidence.** Pulling a host or killing a process can destroy
  volatile evidence (memory, network state) — sequence preservation first.
- **Alerting the adversary.** Premature blocking can tip off an active intruder;
  weigh monitored containment and note it for the approver.
- **Over-reach.** Only propose actions on in-scope assets backed by evidence;
  flag anything speculative as such.
- **Irreversibility.** Call out steps that cannot be undone (wipe/reimage) so the
  approver decides with eyes open.

## Verification

- The plan contains all four NIST phases plus an explicit evidence-preservation
  gate (the `How to Run` check prints "plan sections present").
- Every step has an owner, a `required_approval` value, and a rollback; no step is
  owned by the agent for execution.
- Each eradication/recovery step references a specific finding (timeline row,
  IOC, or alert id) from the case.
