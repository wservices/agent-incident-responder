#!/usr/bin/env bash
# Install the incident-responder APT tool layer on Kali Rolling, then verify.
# Delegates to the shared installer when available; otherwise falls back to apt.
# The pip tools (volatility3, plaso/log2timeline) are installed separately — see
# tools/README.md — because they are not APT packages.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="${HERE}/packages.txt"
VERIFY="${HERE}/verify.txt"

SHARED_INSTALLER="${SECURITY_TOOLING_DIR:-}/skills/security-tooling/scripts/install_from_manifest.sh"
if [ -n "${SECURITY_TOOLING_DIR:-}" ] && [ -x "$SHARED_INSTALLER" ]; then
  bash "$SHARED_INSTALLER" "$MANIFEST" --verify-bin "$(paste -sd, "$VERIFY")"
else
  SUDO=(); [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1 && SUDO=(sudo -n)
  mapfile -t PKGS < <(grep -vE '^\s*(#|$)' "$MANIFEST" | sed 's/#.*//' | awk 'NF{print $1}')
  "${SUDO[@]}" apt-get update -qq
  DEBIAN_FRONTEND=noninteractive "${SUDO[@]}" apt-get install -y --no-install-recommends "${PKGS[@]}"
  missing=0
  while IFS= read -r b; do command -v "$b" >/dev/null 2>&1 || { echo "MISSING $b" >&2; missing=1; }; done < <(grep -vE '^\s*(#|$)' "$VERIFY")
  [ "$missing" -eq 0 ] && echo "incident-responder tools verified" || { echo "verification failed" >&2; exit 1; }
fi
