# incident-responder tools

| Tool | Purpose | Source | Risk |
|---|---|---|---|
| jq | parse/filter JSON (Wazuh, enrichment, handoff) | base image / apt | low |
| ripgrep (`rg`) | fast evidence/string search | base / apt | low |
| tshark | CLI PCAP/packet analysis (offline) | base / apt | live capture needs NET_RAW |
| yara | static pattern match on suspect files | apt (`yara`) | low (no execution of sample) |
| sleuthkit (`fls`,`mactime`,`mmls`) | filesystem timelines from images | apt (`sleuthkit`) | reads images; mounting needs loop/nbd |
| exiftool | file metadata extraction | apt (`libimage-exiftool-perl`) | low |
| volatility3 (`vol`) | **memory** forensics | pip (NOT apt) | reads memory images |
| plaso (`log2timeline.py`,`psort.py`,`pinfo.py`) | super-timelines | pip (NOT apt) | reads images/artifacts |

## Install

```bash
# APT layer, with the shared installer (preferred)
SECURITY_TOOLING_DIR=/path/to/security-tooling bash tools/install.sh
# standalone fallback (apt only)
bash tools/install.sh
```

### Non-apt tools (pip)

`volatility3` and `plaso`/`log2timeline` are **not** APT packages on Kali; install
them with pip into an isolated environment (pipx or a venv keeps them off the
system Python):

```bash
pipx install volatility3        # provides `vol`
pipx install plaso              # provides log2timeline.py, psort.py, pinfo.py
# or: python3 -m venv ~/.ir-tools && ~/.ir-tools/bin/pip install volatility3 plaso
```

plaso has heavy native dependencies (libyal). If pip build fails, use the
official plaso Docker image (`log2timeline/plaso`) mounting the evidence `:ro`.

## Verify

```bash
# via the shared skill's verifier (APT tools)
bash /path/to/security-tooling/skills/security-tooling/scripts/verify_tools.sh --from-file tools/verify.txt
# pip tools
vol --info >/dev/null && log2timeline.py --version && psort.py --version
```

## Capabilities

Analysis is unprivileged and offline. **Static** malware triage never executes a
sample. Mounting a disk image for `fls`/`mactime` needs loop/nbd device access via
`docker_extra_args` (and a read-only mount) — never `--privileged` (Security
Policy §4). Live packet capture (`tshark`) would need `--cap-add NET_RAW`, but this
role works on captured PCAP copies, so it is not required by default.
