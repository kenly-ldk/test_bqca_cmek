#!/usr/bin/env bash
# Tear down the validation estate.
#
# Deletes BOTH projects. This is the only way to remove the Cloud KMS key rings
# — key rings and keys cannot be deleted individually, only their versions
# destroyed. Requires explicit confirmation.
source "$(dirname "${BASH_SOURCE[0]}")/prelude.sh"

cat <<EOF

This will DELETE the following projects and everything in them:

  ${PROJECT_ID}
  ${ROGUE_PROJECT_ID}

Projects enter a 30-day soft-delete window and can be restored with
'gcloud projects undelete' during that period.

EOF
read -r -p "Type the workload project ID to confirm: " CONFIRM
if [[ "${CONFIRM}" != "${PROJECT_ID}" ]]; then
  echo "Aborted — input did not match."
  exit 1
fi

for P in "${PROJECT_ID}" "${ROGUE_PROJECT_ID}"; do
  log "Deleting ${P}"
  gcloud projects delete "${P}" --quiet
done

# Only what config/shared.env.local explicitly names. Reconstructing a name
# such as "admin--<project-id>" would bake one workstation's personal convention
# into shared code: on a fork it either silently does nothing, or deletes a
# gcloud configuration the operator never associated with this estate.
remove_local_state() {  # $1=gcloud configuration name  $2=credentials file
  local cfg="$1" creds="$2"
  if [[ -n "${cfg}" ]]; then
    if gcloud config configurations delete "${cfg}" --quiet 2>/dev/null; then
      echo "  removed gcloud configuration ${cfg}"
    else
      echo "  could not remove gcloud configuration ${cfg} — absent, or active;"
      echo "  if active, switch away with 'gcloud config configurations activate default' first"
    fi
  fi
  if [[ -n "${creds}" && -f "${creds}" ]]; then
    rm -f "${creds}"
    echo "  removed ${creds}"
  fi
}

log "Removing local gcloud state named in config/shared.env.local"
if [[ -z "${GCLOUD_CONFIG_NAME:-}${ROGUE_GCLOUD_CONFIG_NAME:-}${GCP_CREDENTIALS_FILE:-}${ROGUE_GCP_CREDENTIALS_FILE:-}" ]]; then
  echo "  nothing named — local gcloud state left untouched. Remove any"
  echo "  configurations and ADC files for these projects by hand."
else
  remove_local_state "${GCLOUD_CONFIG_NAME:-}" "${GCP_CREDENTIALS_FILE:-}"
  remove_local_state "${ROGUE_GCLOUD_CONFIG_NAME:-}" "${ROGUE_GCP_CREDENTIALS_FILE:-}"
fi

log "Teardown complete. The pyenv virtualenv gda-cmek-val is left in place."
