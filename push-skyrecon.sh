#!/usr/bin/env bash
#
# Replace everything in Ganatra-Ruchir/skyrecon with the new SkyRecon 2.0.0.
#
#   1. Put this script and skyrecon-2.0.0.zip in the same folder.
#   2. bash push-skyrecon.sh
#
# It clones the repo, deletes every tracked file, copies the new project in,
# and pushes one commit. Git history is preserved — nothing is force-pushed —
# so the old version stays reachable in the log if you ever want it back.

set -euo pipefail

REPO="https://github.com/Ganatra-Ruchir/skyrecon.git"
ZIP="skyrecon-2.0.0.zip"
WORK="$(mktemp -d)"

command -v git >/dev/null || { echo "git is not installed"; exit 1; }
command -v unzip >/dev/null || { echo "unzip is not installed"; exit 1; }
[ -f "$ZIP" ] || { echo "$ZIP not found — put it next to this script"; exit 1; }

echo "==> cloning"
git clone --quiet "$REPO" "$WORK/repo"

echo "==> unpacking $ZIP"
unzip -q "$ZIP" -d "$WORK/new"

echo "==> clearing the old tree (keeping .git)"
cd "$WORK/repo"
find . -mindepth 1 -maxdepth 1 -not -name .git -exec rm -rf {} +

echo "==> copying the new project in"
cp -R "$WORK/new/skyrecon/." .

echo "==> committing"
git add -A
git -c user.name="Ruchir Ganatra" \
    -c user.email="$(git config user.email 2>/dev/null || echo 'you@example.com')" \
    commit -q -m "SkyRecon 2.0.0: encrypted-at-rest threat intelligence platform

Complete rewrite. The previous repository contained only a README describing a
Flask + React application; no implementation was present.

- Per-field AES-256-GCM encryption with AAD binding and blind indexes
- Argon2id, rotating refresh tokens with family revocation, TOTP MFA, RBAC
- Hash-chained tamper-evident audit log
- IOC extraction and scoring, a parsed (never eval'd) rule language,
  Isolation Forest anomaly detection, MITRE ATT&CK mapping, STIX/MISP export
- FastAPI service with a buildless CSP-clean dashboard
- 60 tests, ruff, bandit and pip-audit clean
- Docker, Compose, Render, Fly, Railway and Vercel deployment configs"

echo "==> pushing"
git push origin HEAD

echo
echo "done — https://github.com/Ganatra-Ruchir/skyrecon"
echo "the old files are gone from main but still in the git history."
rm -rf "$WORK"
