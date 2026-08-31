-- Layer 5 regulatory compliance view: latest scan only.
--
-- This replaces §3.4 of docs/design.md. Two corrections were forced by testing
-- the original against a live project:
--
--   1. The original selects FROM `governance_project.cloud_asset_inventory
--      .latest_resources`, i.e. a Cloud Asset Inventory BigQuery export.
--      Verified: CAI ExportAssets returns geminidataanalytics DataAgent assets
--      only intermittently — 1 of 7 exports of the same project returned them,
--      the other 6 returned none (each polled to done=True first). A report
--      built on it therefore reads "fully compliant" most of the time while
--      appearing to work. The inventory is instead populated by layer5/scanner,
--      which uses CAI SearchAllResources — consistent on every attempt — plus a
--      live-API cross-check.
--
--   2. The original writes JSON_VALUE(resource.data.kmsKey). In the CAI export
--      schema `resource.data` is a STRING, so that expression fails outright
--      with "Cannot access field kmsKey on a value with type STRING". The
--      correct form is JSON_VALUE(resource.data, '$.kmsKey').
--
-- The approved-KMS-project allowlist is resolved at scan time by the scanner
-- (shared with the Layer 4 enforcer via common/gda_common.py) so the real-time
-- and periodic controls can never disagree about the same resource.
CREATE OR REPLACE VIEW `${PROJECT_ID}.${BQ_DATASET}.${COMPLIANCE_VIEW}` AS
WITH latest AS (
  SELECT MAX(scan_time) AS scan_time
  FROM `${PROJECT_ID}.${BQ_DATASET}.${INVENTORY_TABLE}`
)
SELECT
  i.scan_time,
  -- DATA_AGENT rows are one per agent. CONVERSATION_KEY rows are one per
  -- project+location, summarising every conversation there: CMEK is opt-in per
  -- conversation, so the verdict covers all of them, but conversations are
  -- ephemeral so they are not inventoried individually. Filter on this when a
  -- query means one or the other; agent-count reconciliation must exclude
  -- CONVERSATION_KEY.
  IFNULL(i.resource_type, 'DATA_AGENT') AS resource_type,
  i.resource_url,
  i.project_id,
  i.location,
  i.agent_id,
  i.configured_kms_key,
  i.kms_key_project,
  i.compliance_status,
  i.reason,
  i.visible_in_cai,
  i.visible_in_api,
  -- Three states, not two. A two-valued summary has to file "we could not check
  -- it" as either a pass or a violation, and both are wrong: the first hides
  -- exposure, the second buries real findings in noise. This is the same
  -- distinction Layer 4 makes when it fails closed, carried into the
  -- regulator-facing artifact.
  --
  --   is_compliant   affirmatively verified COMPLIANT. Unchanged and strict —
  --                  existing consumers keep their meaning.
  --   is_violation   affirmatively non-compliant. THIS is the regulator's list.
  --                  Excludes the UNVERIFIABLE statuses: not knowing an agent's
  --                  state is an operational failure to chase, not a finding to
  --                  report as a breach.
  --   verification_state
  --                  the full picture in one column.
  --
  -- PENDING_CAI_INGESTION is neither. It can ONLY be assigned to an agent the
  -- live API listed AND verified as compliant — the scanner requires
  -- verdict.is_compliant before applying it, so it can never mask a violation
  -- (a non-compliant agent absent from CAI keeps its real status). The only
  -- thing missing is second-source corroboration, so filing it as a violation
  -- would report our own indexing lag as a customer's breach.
  i.compliance_status = 'COMPLIANT' AS is_compliant,
  i.compliance_status IN (
    'NON_COMPLIANT_MISSING_CMEK',
    'NON_COMPLIANT_UNAPPROVED_KEY_PROJECT',
    'NON_COMPLIANT_CMEK_UNSUPPORTED_LOCATION'
  ) AS is_violation,
  CASE i.compliance_status
    WHEN 'COMPLIANT' THEN 'VERIFIED_COMPLIANT'
    WHEN 'PENDING_CAI_INGESTION' THEN 'COMPLIANT_PENDING_CORROBORATION'
    WHEN 'NON_COMPLIANT_UNVERIFIABLE' THEN 'UNVERIFIED'
    WHEN 'NON_COMPLIANT_UNVERIFIABLE_SCAN_ERROR' THEN 'UNVERIFIED'
    -- CONVERSATION_KEY rows only. NOT a pass, and deliberately not a separate
    -- reassuring state either: a conversation is readable only by the principal
    -- that created it, so the scanner sees only its own and can never enumerate
    -- the surface. "I saw nothing" and "there is nothing" are indistinguishable
    -- here, so both report UNVERIFIED (validation-report F8).
    WHEN 'NON_COMPLIANT_UNVERIFIABLE_CONVERSATIONS' THEN 'UNVERIFIED'
    ELSE 'VERIFIED_VIOLATION'
  END AS verification_state
FROM `${PROJECT_ID}.${BQ_DATASET}.${INVENTORY_TABLE}` AS i
JOIN latest USING (scan_time);
