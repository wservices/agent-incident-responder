# incident-responder

Hermes cybersecurity agent: **Incident Response Analyst**. Owns the
confirmed-incident lifecycle end to end per NIST SP 800-61r2 — scopes and triages
the incident and starts the IR clock, performs safe **static** malware triage (no
detonation), reconstructs forensic timelines, extracts/defangs/enriches IOCs,
correlates SIEM/EDR alerts across hosts into one incident, and proposes
containment/eradication/recovery with an evidence-backed incident report. Receives
escalations from the SOC Analyst (`security-analyst`) and escalates major
incidents to the Security Team Lead. Advisory and read-only: it **proposes**
response actions; humans execute them.

See `ROLE.md` for the full role definition, permitted/prohibited actions, and
escalation paths.

## Skills

| Skill | What it does |
|---|---|
| `incident-triage-and-scoping` | Classify severity, scope affected assets, start the IR clock (NIST 800-61) |
| `static-malware-triage` | Safe static file triage — hash/strings/PE-ELF/YARA, **no detonation** |
| `forensic-timeline-reconstruction` | Host/super-timeline from logs + artifacts (plaso, Sleuth Kit mactime) |
| `ioc-extraction-and-enrichment` | Extract + defang + enrich IOCs (VirusTotal/MISP optional) |
| `siem-alert-correlation` | Correlate related alerts across hosts/time into one incident (read-only Wazuh) |
| `containment-and-recovery-planning` | Propose containment/eradication/recovery — never executes them |
| `incident-reporting` | NIST-style incident report + validated `handoff.yaml` |

Additional IR skills (memory forensics, disk-image triage, EDR response
orchestration, lessons-learned) are tracked as planned in
`agents/platform/IMPLEMENTATION.md`.

## Install into Hermes (as a profile)

This repo is a **Hermes profile distribution** (`distribution.yaml` + `SOUL.md` +
`skills/`). Install it as its own agent profile:

```bash
hermes profile install "https://github.com/wservices/agent-incident-responder.git"
hermes -p incident-responder chat            # run the responder (one-off, no sticky change)
hermes profile use incident-responder        # ...or make it the sticky default, then `hermes chat`
hermes profile update incident-responder     # re-pull later; keeps your .env/memory
```

Then add the recommended companion skills (install the ones you need):

```bash
# CVE context + IOC/OSINT enrichment
hermes skills install "https://raw.githubusercontent.com/wservices/skill-cve-research/main/skills/cve-research/SKILL.md" --category security
hermes skills install "https://raw.githubusercontent.com/wservices/skill-passive-reconnaissance/main/skills/passive-reconnaissance/SKILL.md" --category security
# analysis tooling + reporting
hermes skills install "https://raw.githubusercontent.com/wservices/skill-security-tooling/main/skills/security-tooling/SKILL.md" --category security
hermes skills install "https://raw.githubusercontent.com/wservices/skill-tool-intel/main/skills/tool-intel/SKILL.md" --category devops
hermes skills install "https://raw.githubusercontent.com/wservices/skill-markdown-to-pdf/main/skills/markdown-to-pdf/SKILL.md" --category documents
```

These general skills aren't bundled in the profile but pair well with incident
response — all read-only / analysis-only, in keeping with the role:

| Skill | Why |
|---|---|
| `cve-research` | enrich a CVE behind the incident across NVD / KEV / EPSS / OSV for severity + exploit maturity |
| `passive-reconnaissance` | enrich IOC domains/IPs from public OSINT, without scanning or resolving them live |
| `security-tooling` | install/verify the Kali analysis tools the role uses |
| `tool-intel` | learn/verify those CLI tools (yara, plaso, Sleuth Kit) and detect version drift |
| `markdown-to-pdf` | render the incident report (`report.md` → PDF) for distribution |

Planned (not yet hosted — no install command): `mitre-attack` (ATT&CK technique
mapping), `security-reporting` (report structure/templating), and
`evidence-handling` (chain-of-custody + hashing discipline).

On install, Hermes generates a `.env.EXAMPLE` from `distribution.yaml`'s
`env_requires` (Wazuh + optional VirusTotal/MISP vars). Copy it to `.env`, fill in
your values, and forward the names into the Kali sandbox via `docker_forward_env`.
`config.yaml` is **not** overwritten (your model/provider is preserved).

**See [`docs/ENVIRONMENT.md`](docs/ENVIRONMENT.md)** for every variable this role
reads — required/optional, defaults, a copy-ready `.env` template, the
`docker_forward_env` snippet, and the secret-handling rules. That file is
generated from `distribution.yaml` (`agents/platform/scripts/gen_env_doc.py`), so
it never drifts from what the role actually uses.

The companion skills above install from the public mirror; for the internal
pinned (CI) install path and the profile + shared-skill mechanism, see
`agents/platform/docs/GITLAB-ARCHITECTURE.md` and `HERMES-INTEGRATION.md` §6.

## Tools

`tools/packages.txt` + `tools/install.sh` install the APT tool layer
(`yara sleuthkit tshark jq ripgrep exiftool`). Two tools are **not** apt packages
and are installed via pip (see `tools/README.md`): `volatility3` (memory
forensics) and `plaso`/`log2timeline` (super-timelines). All analysis is
unprivileged and offline; mounting a disk image for forensics needs loop/nbd
device access via `docker_extra_args` — never `--privileged` (Security Policy §4).
Static malware triage never executes the sample.

## Tests

```bash
python3 -m pytest tests -q     # offline scaffold smoke test (manifest + SKILL metadata/structure)
```

## Security

Bound by `agents/platform/policies/SECURITY-POLICY.md`: read-only and advisory by
default, no response actions (containment/eradication/recovery are *proposed*, not
executed), **no detonation** of samples (static triage only), evidence preserved
(hashed copies, read-only mounts), secrets never committed/logged, and untrusted
content (malware strings, logs, alerts) treated as data, never instructions. Real
case data and evidence are gitignored and never committed.

## License

MIT.
