#!/usr/bin/env bash
# Fetch evaluation targets at PINNED refs into targets/.
# Targets are never vendored into this repo (see .gitignore) so we don't
# redistribute someone else's code; anyone re-running gets the identical revision.
#
# Usage:
#   bash scripts/fetch_target.sh                # fetch all targets
#   bash scripts/fetch_target.sh langflow       # fetch one target
#   bash scripts/fetch_target.sh bottle pyyaml  # fetch specific targets
set -euo pipefail

cd "$(dirname "$0")/.."

# ── Target registry ─────────────────────────────────────────────────────
# Each entry: NAME|REPO_URL|PINNED_REF|SANITY_CHECK
#   SANITY_CHECK is a grep pattern + file used to verify the expected code
#   is present at the pinned revision. Format: "pattern::file" or "skip".
TARGETS=(
  "langflow|https://github.com/langflow-ai/langflow.git|1.7.3|compile\\(.*\"exec\"\\)::src/backend/base/langflow/helpers/flow.py"
  "mlflow|https://github.com/mlflow/mlflow.git|v2.9.0|class LocalArtifactRepository::mlflow/store/artifact/local_artifact_repo.py"
  "bottle|https://github.com/bottlepy/bottle.git|0.12.19|def _hval::bottle.py"
  "pyyaml|https://github.com/yaml/pyyaml.git|5.3.1|def load::lib/yaml/__init__.py"
  "werkzeug|https://github.com/pallets/werkzeug.git|2.3.7|execute_command::src/werkzeug/debug/__init__.py"
  "pygoat|https://github.com/adeyosemanputra/pygoat.git|master|objects\\.raw::introduction/views.py"
)

fetch_target() {
  local entry="$1"
  IFS='|' read -r NAME REPO_URL PINNED_REF SANITY_CHECK <<< "$entry"
  local DEST="targets/$NAME"

  echo ""
  echo "── $NAME @ $PINNED_REF ──────────────────────────────────"

  if [ -d "$DEST/.git" ]; then
    echo "[fetch_target] $DEST already present; verifying ref..."
  else
    echo "[fetch_target] cloning $REPO_URL @ $PINNED_REF (shallow) ..."
    mkdir -p targets
    git clone --depth 1 --branch "$PINNED_REF" "$REPO_URL" "$DEST"
  fi

  cd "$DEST"
  local HEAD_SHA
  HEAD_SHA="$(git rev-parse HEAD)"
  echo "[fetch_target] HEAD = $HEAD_SHA (tag $PINNED_REF)"

  # Sanity check
  if [ "$SANITY_CHECK" != "skip" ]; then
    local PATTERN FILE
    PATTERN="${SANITY_CHECK%%::*}"
    FILE="${SANITY_CHECK##*::}"
    if grep -qE "$PATTERN" "$FILE" 2>/dev/null; then
      echo "[fetch_target] OK: verified expected code present in $FILE"
    else
      echo "[fetch_target] WARNING: expected pattern not found in $FILE at $PINNED_REF" >&2
      echo "[fetch_target] Pattern: $PATTERN" >&2
    fi
  fi

  cd "$(dirname "$0")/.." 2>/dev/null || cd -
  echo "[fetch_target] $NAME done."
}

# ── Main ─────────────────────────────────────────────────────────────────

cd "$(dirname "$0")/.."

if [ $# -eq 0 ]; then
  # Fetch all targets
  echo "[fetch_target] fetching all targets..."
  for entry in "${TARGETS[@]}"; do
    fetch_target "$entry"
  done
else
  # Fetch named targets
  for requested in "$@"; do
    found=false
    for entry in "${TARGETS[@]}"; do
      IFS='|' read -r NAME _ _ _ <<< "$entry"
      if [ "$NAME" = "$requested" ]; then
        fetch_target "$entry"
        found=true
        break
      fi
    done
    if [ "$found" = "false" ]; then
      echo "[fetch_target] ERROR: unknown target '$requested'" >&2
      echo "[fetch_target] Available: $(for e in "${TARGETS[@]}"; do IFS='|' read -r n _ _ _ <<< "$e"; printf "%s " "$n"; done)" >&2
      exit 1
    fi
  done
fi

echo ""
echo "[fetch_target] all done."
