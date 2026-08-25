#!/usr/bin/env bash
# Render committed templates into the concrete files the tooling consumes.
#
# Same split as config/shared.env vs shared.env.local: *.example.* files are
# committed and carry ${VAR} placeholders; the rendered outputs contain real
# project IDs and are gitignored. Idempotent.
source "$(dirname "${BASH_SOURCE[0]}")/../scripts/prelude.sh"

render() {  # $1=template  $2=output
  # Only the vars we own — plain envsubst would eat any other $... in the text.
  sed -e "s|\${PROJECT_ID}|${PROJECT_ID}|g" \
      -e "s|\${ROGUE_PROJECT_ID}|${ROGUE_PROJECT_ID}|g" \
      -e "s|\${LOCATION}|${LOCATION}|g" \
      -e "s|\${KMS_KEYRING}|${KMS_KEYRING}|g" \
      -e "s|\${KMS_KEY}|${KMS_KEY}|g" \
      -e "s|\${ROGUE_KMS_KEYRING}|${ROGUE_KMS_KEYRING}|g" \
      -e "s|\${ROGUE_KMS_KEY}|${ROGUE_KMS_KEY}|g" \
      -e "s|\${BQ_SOURCE_DATASET}|${BQ_SOURCE_DATASET}|g" \
      -e "s|\${BQ_SOURCE_TABLE}|${BQ_SOURCE_TABLE}|g" \
      "$1" > "$2"
  echo "  rendered $(basename "$2")"
}

log "Rendering Layer 1 manifests for ${PROJECT_ID}"
for TPL in "${REPO_ROOT}"/layer1/manifests/*.example.json; do
  render "${TPL}" "${TPL/.example.json/.json}"
done

# The OPA allowlist data file: the environment's real approved KMS projects.
CONFIG_DIR="${REPO_ROOT}/layer1/config"
python - "${CONFIG_DIR}/approved-kms-projects.json" "${APPROVED_KMS_PROJECTS}" <<'PY'
import json, sys
path, raw = sys.argv[1], sys.argv[2]
projects = [p.strip() for p in raw.split(",") if p.strip()]
with open(path, "w") as fh:
    json.dump({"config": {"approved_kms_projects": projects}}, fh, indent=2)
    fh.write("\n")
print(f"  rendered approved-kms-projects.json ({projects})")
PY
