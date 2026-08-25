-- Layer 5 inventory table. One row per agent per scan.
--
-- Deliberately stores metadata only. The agent's publishedContext is the
-- customer content CMEK exists to protect; copying it into a compliance table
-- would create a second, differently-encrypted copy of exactly the data under
-- audit. Columns here are limited to what a regulator needs to see.
CREATE TABLE IF NOT EXISTS `${PROJECT_ID}.${BQ_DATASET}.${INVENTORY_TABLE}`
(
  scan_time          TIMESTAMP NOT NULL OPTIONS(description="UTC time of the scan run"),
  -- DATA_AGENT: one row per agent.
  -- CONVERSATION_KEY: one row per project+location. CMEK for conversations is a
  -- project+location singleton (the API rejects any second key, even one in the
  -- same project), so there is nothing per-conversation to inventory —
  -- conversations are ephemeral and never provisioned. The control is a single
  -- attestation of the registered key. See common/gda_common.attest_conversation_key.
  resource_type      STRING    OPTIONS(description="DATA_AGENT | CONVERSATION_KEY"),
  resource_url       STRING    NOT NULL OPTIONS(description="agent path, or the conversations collection for an attestation"),
  project_id         STRING,
  location           STRING,
  agent_id           STRING,
  configured_kms_key STRING    OPTIONS(description="CMEK key path, NULL if none"),
  kms_key_project    STRING    OPTIONS(description="Project extracted from the key path"),
  compliance_status  STRING    NOT NULL,
  reason             STRING,
  visible_in_cai     BOOL      OPTIONS(description="Returned by CAI SearchAllResources"),
  visible_in_api     BOOL      OPTIONS(description="Returned by the live dataAgents.list")
)
PARTITION BY DATE(scan_time)
CLUSTER BY compliance_status, project_id
OPTIONS(description="GDA DataAgent CMEK compliance inventory (Layer 5).");
