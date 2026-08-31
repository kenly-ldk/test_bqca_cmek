#!/usr/bin/env bash
# Deploy the shared control plane: Layers 2, 4 and 5.
# Idempotent; safe to re-run.
#
# These three are deployed ONCE and govern both resource types. There is no
# agent copy and conversation copy — one persona set, one enforcer function, one
# scanner job, each handling agents and conversations through different
# mechanics inside the same deployment. That is why the setup and test scripts
# split per resource type but the control-plane deploy does not:
#
#   Layer 2  the personas, incl. the gdaConversationUser custom role
#   Layer 4  one log sink matching BOTH CreateDataAgent (Admin Activity) and
#            TopicService.CreateTopic (Data Access), into one function
#   Layer 5  one scanner reporting per agent AND per conversation location
#
# The per-resource halves are scripts/deploy_agents.sh and
# scripts/deploy_conversations.sh — run this first, then either or both.
#
#   bash scripts/deploy_controls.sh
source "$(dirname "${BASH_SOURCE[0]}")/prelude.sh"

# Layer 2 first, on purpose: IAM takes ~60-120 s to propagate, and that wait
# then overlaps with the two builds below rather than being paid on its own.
log "Layer 2 — the least-privilege personas"
bash "${REPO_ROOT}/layer2/deploy.sh"

# Always dry-run on the first deploy. A filter bug in this class of control
# deletes compliant production agents; scripts/deploy_agents.sh --enforce is
# what flips it, after you have watched it classify a known-good agent.
log "Layer 4 — detection and remediation, in DRY RUN"
DRY_RUN=true bash "${REPO_ROOT}/layer4/deploy.sh"

log "Layer 5 — continuous compliance reporting"
bash "${REPO_ROOT}/layer5/deploy.sh"

log "Shared control plane deployed in ${PROJECT_ID}"
cat <<EOF

Layer 4 is in DRY RUN: it classifies and logs, and deletes nothing. Leave it
there until you have seen it rule on an agent you know to be compliant.

Now deploy whichever resource types you are governing:

  bash scripts/deploy_agents.sh          # Layer 3 -> a datasource and a CMEK agent
  bash scripts/deploy_conversations.sh   # Layer 3 -> a CMEK conversation per location
EOF
