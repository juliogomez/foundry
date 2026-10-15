#!/usr/bin/env bash
# Fetch Project CodeGuard's core Cursor rules at a pinned release, verified by SHA-256.
# Used by the prevention experiment (docs/PREVENTION.md). Output: vendor/codeguard/<version>/rules/*.mdc
set -euo pipefail

VERSION="v1.5.0"
SHA256="4314663a14907cd726da040ae9617cf1036efd7677416769e87a89b6a5a4a63c"
URL="https://github.com/cosai-oasis/project-codeguard/releases/download/${VERSION}/codeguard-cursor.zip"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="${ROOT}/vendor/codeguard/${VERSION}"

if [ -d "${DEST}/rules" ] && ls "${DEST}"/rules/*.mdc >/dev/null 2>&1; then
  echo "CodeGuard ${VERSION} already present at ${DEST}/rules"
  exit 0
fi

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

echo "Downloading CodeGuard ${VERSION} (Cursor bundle)..."
curl -fsSL "${URL}" -o "${TMP}/codeguard-cursor.zip"

ACTUAL="$(shasum -a 256 "${TMP}/codeguard-cursor.zip" | awk '{print $1}')"
if [ "${ACTUAL}" != "${SHA256}" ]; then
  echo "SHA-256 mismatch: expected ${SHA256}, got ${ACTUAL}" >&2
  exit 1
fi

unzip -q "${TMP}/codeguard-cursor.zip" -d "${TMP}/x"
mkdir -p "${DEST}/rules"
cp "${TMP}"/x/.cursor/rules/*.mdc "${DEST}/rules/"
echo "CodeGuard ${VERSION}: $(ls "${DEST}"/rules/*.mdc | wc -l | tr -d ' ') rules -> ${DEST}/rules"
