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
  -- CONVERSATION_KEY: one row per project+location, summarising every
  -- conversation in it. CMEK on a conversation is real but opt-in per
  -- conversation, so all of them are read and the location fails if any one is
  -- unkeyed; the row is a summary because conversations are ephemeral and
  -- hard-deleted. See common/gda_common.evaluate_conversation_compliance.
  resource_type      STRING    OPTIONS(description="DATA_AGENT | CONVERSATION_KEY"),
  resource_url       STRING    NOT NULL OPTIONS(description="agent path, or the conversations collection for a per-location verdict"),
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
