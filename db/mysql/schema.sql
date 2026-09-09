-- ============================================================================
-- SkyRecon 3 — complete MySQL 8 schema
-- Covers every screen in the Threat Operations console:
--   Overview · Alerts · Incidents · Investigations (entity graph) · Live Events
--   Threat Intelligence · Indicators · Threat Actors · ATT&CK · Watchlists
--   Detection Rules · Anomalies · Threat Hunting · Playbooks · Integrations
--   Users & Roles · Audit Trail · System Health · Settings
--
-- Supersedes skyrecon_schema.sql (adds the entity graph, actors, watchlists,
-- playbooks, feed connectors, saved hunts and anomaly scoring tables).
--
-- Encrypted-field convention:
--   <field>_ciphertext  VARBINARY/BLOB  -- AES-256-GCM (nonce + tag inline)
--   <field>_bidx        CHAR(64)        -- keyed HMAC-SHA256 blind index
-- The blind index supports equality lookups only — no ordering, no prefix
-- search, no reversal. That is deliberate.
-- ============================================================================

-- Statement 21 of the previous file failed with error 1064 because `signal`
-- is a reserved word in MySQL 8. That left the schema half-built, so this file
-- drops and recreates it. The database held no data at that point — if yours
-- now does, comment the DROP out and run the REPAIR block at the very bottom.
DROP DATABASE IF EXISTS skyrecon;

CREATE DATABASE IF NOT EXISTS skyrecon
  CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
USE skyrecon;
SET NAMES utf8mb4;

-- ─────────────────────────────────────────────────────────────
-- 1. Identity, access control, sessions
-- ─────────────────────────────────────────────────────────────
CREATE TABLE users (
  id                    BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  email_ciphertext      VARBINARY(512) NOT NULL,
  email_bidx            CHAR(64)       NOT NULL,
  password_hash         VARCHAR(255)   NOT NULL,            -- Argon2id
  role                  ENUM('viewer','analyst','admin') NOT NULL DEFAULT 'viewer',
  display_name          VARCHAR(120)   NOT NULL,
  mfa_enabled           TINYINT UNSIGNED     NOT NULL DEFAULT 0,
  mfa_secret_ciphertext VARBINARY(512) NULL,
  failed_attempts       SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  locked_until          DATETIME NULL,
  disabled_at           DATETIME NULL,
  last_login_at         DATETIME NULL,
  created_at            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uq_users_email_bidx (email_bidx),
  KEY idx_users_role (role)
) ENGINE=InnoDB;

CREATE TABLE refresh_tokens (
  id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id     BIGINT UNSIGNED NOT NULL,
  token_hash  CHAR(64) NOT NULL,
  user_agent  VARCHAR(255) NULL,
  ip          VARCHAR(45)  NULL,
  expires_at  DATETIME NOT NULL,
  revoked_at  DATETIME NULL,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_rt_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE KEY uq_rt_hash (token_hash),
  KEY idx_rt_user (user_id)
) ENGINE=InnoDB;

CREATE TABLE api_keys (
  id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id      BIGINT UNSIGNED NOT NULL,
  name         VARCHAR(120) NOT NULL,
  key_hash     CHAR(64) NOT NULL,
  scopes       VARCHAR(255) NOT NULL DEFAULT 'read',
  last_used_at DATETIME NULL,
  revoked_at   DATETIME NULL,
  created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_ak_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE KEY uq_ak_hash (key_hash)
) ENGINE=InnoDB;

-- ─────────────────────────────────────────────────────────────
-- 2. Assets and the entity graph (Investigations screen)
-- ─────────────────────────────────────────────────────────────
CREATE TABLE entities (
  id             BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  kind           ENUM('host','account','process','file','ip','domain','url','alert','zone') NOT NULL,
  name           VARCHAR(255) NOT NULL,          -- display label, e.g. 'DESKTOP-04'
  name_bidx      CHAR(64)     NOT NULL,          -- equality lookup
  risk_score     DECIMAL(5,2) NOT NULL DEFAULT 0,
  criticality    ENUM('low','medium','high','crown_jewel') NOT NULL DEFAULT 'medium',
  attributes     JSON NULL,                      -- os, asn, owner, exposure, prevalence…
  first_seen_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_entity (kind, name_bidx),
  KEY idx_entity_risk (risk_score),
  KEY idx_entity_kind (kind)
) ENGINE=InnoDB;

CREATE TABLE entity_edges (
  id            BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  src_id        BIGINT UNSIGNED NOT NULL,
  dst_id        BIGINT UNSIGNED NOT NULL,
  relation      ENUM('communicated_with','resolved_to','executed','spawned','authenticated_as',
                     'downloaded','triggered','lateral_move','queried_by','implicated','routes') NOT NULL,
  weight        DECIMAL(5,2) NOT NULL DEFAULT 1,
  first_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  observations  INT UNSIGNED NOT NULL DEFAULT 1,
  CONSTRAINT fk_edge_src FOREIGN KEY (src_id) REFERENCES entities(id) ON DELETE CASCADE,
  CONSTRAINT fk_edge_dst FOREIGN KEY (dst_id) REFERENCES entities(id) ON DELETE CASCADE,
  UNIQUE KEY uq_edge (src_id, dst_id, relation),
  KEY idx_edge_dst (dst_id)
) ENGINE=InnoDB;

-- ─────────────────────────────────────────────────────────────
-- 3. MITRE ATT&CK reference
-- ─────────────────────────────────────────────────────────────
CREATE TABLE mitre_techniques (
  id       VARCHAR(16) PRIMARY KEY,      -- 'T1071.001'
  parent_id VARCHAR(16) NULL,            -- 'T1071' for sub-techniques
  name     VARCHAR(160) NOT NULL,
  tactic   VARCHAR(80)  NOT NULL,
  KEY idx_tech_tactic (tactic)
) ENGINE=InnoDB;

-- ─────────────────────────────────────────────────────────────
-- 4. Indicators (encrypted IOC store) + enrichment
-- ─────────────────────────────────────────────────────────────
CREATE TABLE indicators (
  id               BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  type             ENUM('ipv4','ipv6','domain','url','sha256','md5','email','cve') NOT NULL,
  value_ciphertext VARBINARY(2048) NOT NULL,
  value_bidx       CHAR(64) NOT NULL,
  risk_score       DECIMAL(5,2) NOT NULL DEFAULT 0,
  confidence_score DECIMAL(5,2) NOT NULL DEFAULT 0,   -- decays over 30 days
  dga_score        DECIMAL(4,3) NULL,                 -- domains only
  tld_risk         DECIMAL(4,3) NULL,
  entropy          DECIMAL(5,3) NULL,
  sightings_count  INT UNSIGNED NOT NULL DEFAULT 1,
  source           VARCHAR(80) NOT NULL DEFAULT 'manual',
  scoring_rationale TEXT NULL,            -- the sentence shown in the IOC flyout
  first_seen_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  created_by       BIGINT UNSIGNED NULL,
  CONSTRAINT fk_ioc_creator FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
  UNIQUE KEY uq_ioc (type, value_bidx),
  KEY idx_ioc_risk (risk_score),
  KEY idx_ioc_last_seen (last_seen_at),
  KEY idx_ioc_source (source)
) ENGINE=InnoDB;

CREATE TABLE indicator_sightings (
  id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  indicator_id BIGINT UNSIGNED NOT NULL,
  entity_id    BIGINT UNSIGNED NULL,
  observed_at  DATETIME NOT NULL,
  source       VARCHAR(80) NOT NULL,
  CONSTRAINT fk_sight_ioc FOREIGN KEY (indicator_id) REFERENCES indicators(id) ON DELETE CASCADE,
  CONSTRAINT fk_sight_entity FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE SET NULL,
  KEY idx_sight_ioc_time (indicator_id, observed_at)
) ENGINE=InnoDB;

-- ─────────────────────────────────────────────────────────────
-- 5. Threat actors
-- ─────────────────────────────────────────────────────────────
CREATE TABLE threat_actors (
  id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name        VARCHAR(120) NOT NULL,
  aliases     VARCHAR(255) NULL,
  confidence  DECIMAL(5,2) NOT NULL DEFAULT 0,
  sectors     VARCHAR(255) NULL,
  description TEXT NULL,
  last_activity_at DATETIME NULL,
  UNIQUE KEY uq_actor (name)
) ENGINE=InnoDB;

CREATE TABLE actor_techniques (
  actor_id     BIGINT UNSIGNED NOT NULL,
  technique_id VARCHAR(16) NOT NULL,
  PRIMARY KEY (actor_id, technique_id),
  CONSTRAINT fk_at_actor FOREIGN KEY (actor_id) REFERENCES threat_actors(id) ON DELETE CASCADE,
  CONSTRAINT fk_at_tech FOREIGN KEY (technique_id) REFERENCES mitre_techniques(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE actor_indicators (
  actor_id     BIGINT UNSIGNED NOT NULL,
  indicator_id BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (actor_id, indicator_id),
  CONSTRAINT fk_ai_actor FOREIGN KEY (actor_id) REFERENCES threat_actors(id) ON DELETE CASCADE,
  CONSTRAINT fk_ai_ioc FOREIGN KEY (indicator_id) REFERENCES indicators(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ─────────────────────────────────────────────────────────────
-- 6. Watchlists
-- ─────────────────────────────────────────────────────────────
CREATE TABLE watchlists (
  id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name       VARCHAR(160) NOT NULL,
  severity   ENUM('low','medium','high','critical') NOT NULL DEFAULT 'medium',
  created_by BIGINT UNSIGNED NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_wl_user FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
  UNIQUE KEY uq_wl_name (name)
) ENGINE=InnoDB;

CREATE TABLE watchlist_items (
  id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  watchlist_id BIGINT UNSIGNED NOT NULL,
  indicator_id BIGINT UNSIGNED NULL,
  entity_id    BIGINT UNSIGNED NULL,
  note         VARCHAR(500) NULL,
  added_by     BIGINT UNSIGNED NULL,
  created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_wli_list FOREIGN KEY (watchlist_id) REFERENCES watchlists(id) ON DELETE CASCADE,
  CONSTRAINT fk_wli_ioc FOREIGN KEY (indicator_id) REFERENCES indicators(id) ON DELETE CASCADE,
  CONSTRAINT fk_wli_entity FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE CASCADE,
  CONSTRAINT ck_wli_target CHECK (indicator_id IS NOT NULL OR entity_id IS NOT NULL),
  KEY idx_wli_list (watchlist_id)
) ENGINE=InnoDB;

-- ─────────────────────────────────────────────────────────────
-- 7. Detection rules
-- ─────────────────────────────────────────────────────────────
CREATE TABLE rules (
  id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name        VARCHAR(160) NOT NULL,
  expression  VARCHAR(1000) NOT NULL,     -- recursive-descent parsed, never eval()'d
  severity    ENUM('low','medium','high','critical') NOT NULL DEFAULT 'medium',
  enabled     TINYINT UNSIGNED NOT NULL DEFAULT 1,
  fires_30d   INT UNSIGNED NOT NULL DEFAULT 0,   -- denormalised for the rules table
  created_by  BIGINT UNSIGNED NULL,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT fk_rule_user FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
  UNIQUE KEY uq_rule_name (name)
) ENGINE=InnoDB;

-- ─────────────────────────────────────────────────────────────
-- 8. Telemetry events (Live Events / hunting corpus)
-- ─────────────────────────────────────────────────────────────
CREATE TABLE events (
  id                 BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  event_type         ENUM('AUTH','DNS','HTTP','NETWORK','PROCESS','FILE','OTHER') NOT NULL,
  source_ip          VARCHAR(45) NULL,
  destination_ip     VARCHAR(45) NULL,
  destination_host   VARCHAR(255) NULL,
  entity_id          BIGINT UNSIGNED NULL,       -- the asset it happened on
  user_id            BIGINT UNSIGNED NULL,
  protocol           VARCHAR(20) NULL,
  bytes_out          BIGINT UNSIGNED NULL,
  bytes_in           BIGINT UNSIGNED NULL,
  payload_ciphertext VARBINARY(8192) NULL,
  occurred_at        DATETIME(3) NOT NULL,
  ingested_at        DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  CONSTRAINT fk_ev_entity FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE SET NULL,
  CONSTRAINT fk_ev_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
  KEY idx_ev_time (occurred_at),
  KEY idx_ev_type_time (event_type, occurred_at),
  KEY idx_ev_src (source_ip),
  KEY idx_ev_bytes (bytes_out)
) ENGINE=InnoDB;

CREATE TABLE anomaly_scores (
  id            BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  event_id      BIGINT UNSIGNED NOT NULL,
  model         ENUM('isolation_forest','zscore') NOT NULL,
  score         DECIMAL(6,4) NOT NULL,
  top_feature   VARCHAR(60) NULL,          -- e.g. 'bytes_out'
  feature_zscore DECIMAL(6,3) NULL,
  scored_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_as_event FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE,
  KEY idx_as_score (score)
) ENGINE=InnoDB;

-- ─────────────────────────────────────────────────────────────
-- 9. Alerts
-- ─────────────────────────────────────────────────────────────
CREATE TABLE alerts (
  id             BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  public_id      VARCHAR(20) NOT NULL,        -- 'SR-5200'
  title          VARCHAR(200) NOT NULL,
  severity       ENUM('low','medium','high','critical') NOT NULL,
  status         ENUM('open','triaged','investigating','resolved','false_positive') NOT NULL DEFAULT 'open',
  risk_score     DECIMAL(5,2) NOT NULL,
  confidence     DECIMAL(5,2) NOT NULL,
  rule_id        BIGINT UNSIGNED NULL,
  indicator_id   BIGINT UNSIGNED NULL,
  event_id       BIGINT UNSIGNED NULL,
  entity_id      BIGINT UNSIGNED NULL,        -- primary asset
  account_id     BIGINT UNSIGNED NULL,
  source_ip      VARCHAR(45) NULL,
  destination    VARCHAR(255) NULL,
  assigned_to    BIGINT UNSIGNED NULL,
  created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  resolved_at    DATETIME NULL,
  CONSTRAINT fk_al_rule FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE SET NULL,
  CONSTRAINT fk_al_ioc FOREIGN KEY (indicator_id) REFERENCES indicators(id) ON DELETE SET NULL,
  CONSTRAINT fk_al_event FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE SET NULL,
  CONSTRAINT fk_al_entity FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE SET NULL,
  CONSTRAINT fk_al_account FOREIGN KEY (account_id) REFERENCES users(id) ON DELETE SET NULL,
  CONSTRAINT fk_al_assignee FOREIGN KEY (assigned_to) REFERENCES users(id) ON DELETE SET NULL,
  UNIQUE KEY uq_al_public (public_id),
  KEY idx_al_sev_time (severity, created_at),
  KEY idx_al_status (status),
  KEY idx_al_risk (risk_score)
) ENGINE=InnoDB;

-- One row per reason the detection fired — this is what renders in the
-- "Why SkyRecon flagged this" block, so it must be queryable, not a blob.
CREATE TABLE alert_reasons (
  id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  alert_id   BIGINT UNSIGNED NOT NULL,
  ordinal    TINYINT UNSIGNED NOT NULL,
  reason     VARCHAR(500) NOT NULL,
  signal_name VARCHAR(80) NULL,           -- 'ioc_match','zscore','entropy',…
  value      DECIMAL(10,4) NULL,
  CONSTRAINT fk_ar_alert FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE,
  UNIQUE KEY uq_ar (alert_id, ordinal)
) ENGINE=InnoDB;

CREATE TABLE alert_techniques (
  alert_id     BIGINT UNSIGNED NOT NULL,
  technique_id VARCHAR(16) NOT NULL,
  PRIMARY KEY (alert_id, technique_id),
  CONSTRAINT fk_alt_alert FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE,
  CONSTRAINT fk_alt_tech FOREIGN KEY (technique_id) REFERENCES mitre_techniques(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ─────────────────────────────────────────────────────────────
-- 10. Incidents & investigations
-- ─────────────────────────────────────────────────────────────
CREATE TABLE incidents (
  id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  public_id   VARCHAR(24) NOT NULL,          -- 'INC-2026-042'
  title       VARCHAR(200) NOT NULL,
  severity    ENUM('low','medium','high','critical') NOT NULL,
  status      ENUM('new','investigating','contained','resolved') NOT NULL DEFAULT 'new',
  owner_id    BIGINT UNSIGNED NULL,
  resolution  VARCHAR(500) NULL,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  resolved_at DATETIME NULL,
  CONSTRAINT fk_inc_owner FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE SET NULL,
  UNIQUE KEY uq_inc_public (public_id),
  KEY idx_inc_status (status)
) ENGINE=InnoDB;

CREATE TABLE incident_alerts (
  incident_id BIGINT UNSIGNED NOT NULL,
  alert_id    BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (incident_id, alert_id),
  CONSTRAINT fk_ia_inc FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
  CONSTRAINT fk_ia_alert FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE incident_entities (
  incident_id BIGINT UNSIGNED NOT NULL,
  entity_id   BIGINT UNSIGNED NOT NULL,
  role        VARCHAR(40) NULL,             -- 'patient_zero','pivot','target'
  PRIMARY KEY (incident_id, entity_id),
  CONSTRAINT fk_ie_inc FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
  CONSTRAINT fk_ie_entity FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE investigation_timeline (
  id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  incident_id BIGINT UNSIGNED NOT NULL,
  stage       ENUM('access','execution','persistence','c2','exfiltration','lateral','detection','note') NOT NULL,
  description VARCHAR(1000) NOT NULL,
  entity_id   BIGINT UNSIGNED NULL,
  signal_name VARCHAR(120) NULL,           -- 'z-score 6.1', 'DGA 0.81'
  occurred_at DATETIME(3) NOT NULL,
  created_by  BIGINT UNSIGNED NULL,
  CONSTRAINT fk_it_inc FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
  CONSTRAINT fk_it_entity FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE SET NULL,
  CONSTRAINT fk_it_user FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
  KEY idx_it_inc_time (incident_id, occurred_at)
) ENGINE=InnoDB;

-- ─────────────────────────────────────────────────────────────
-- 11. Hunting, playbooks, integrations
-- ─────────────────────────────────────────────────────────────
CREATE TABLE saved_hunts (
  id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name       VARCHAR(160) NOT NULL,
  query      TEXT NOT NULL,
  created_by BIGINT UNSIGNED NULL,
  last_run_at DATETIME NULL,
  last_hits  INT UNSIGNED NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_hunt_user FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
  UNIQUE KEY uq_hunt_name (name)
) ENGINE=InnoDB;

CREATE TABLE playbooks (
  id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name         VARCHAR(160) NOT NULL,
  trigger_expr VARCHAR(500) NOT NULL,
  enabled      TINYINT UNSIGNED NOT NULL DEFAULT 0,
  created_by   BIGINT UNSIGNED NULL,
  created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_pb_user FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
  UNIQUE KEY uq_pb_name (name)
) ENGINE=InnoDB;

-- Only reversible action types are modelled on purpose. Blocking/isolation
-- is deliberately absent until there is a human approval step to attach it to.
CREATE TABLE playbook_steps (
  id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  playbook_id BIGINT UNSIGNED NOT NULL,
  ordinal     TINYINT UNSIGNED NOT NULL,
  action      ENUM('enrich_ioc','check_reputation','create_incident','assign_analyst',
                   'add_watchlist','notify','tag','attach_baseline') NOT NULL,
  params      JSON NULL,
  CONSTRAINT fk_pbs_pb FOREIGN KEY (playbook_id) REFERENCES playbooks(id) ON DELETE CASCADE,
  UNIQUE KEY uq_pbs (playbook_id, ordinal)
) ENGINE=InnoDB;

CREATE TABLE playbook_runs (
  id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  playbook_id BIGINT UNSIGNED NOT NULL,
  alert_id    BIGINT UNSIGNED NULL,
  status      ENUM('running','succeeded','failed') NOT NULL DEFAULT 'running',
  log         JSON NULL,
  started_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  finished_at DATETIME NULL,
  CONSTRAINT fk_pbr_pb FOREIGN KEY (playbook_id) REFERENCES playbooks(id) ON DELETE CASCADE,
  CONSTRAINT fk_pbr_alert FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE feed_connectors (
  id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name            VARCHAR(80) NOT NULL,          -- 'URLhaus','ThreatFox','AbuseIPDB'…
  status          ENUM('connected','disabled','error','not_configured') NOT NULL DEFAULT 'not_configured',
  api_key_ciphertext VARBINARY(1024) NULL,
  sync_interval_min SMALLINT UNSIGNED NOT NULL DEFAULT 15,
  last_sync_at    DATETIME NULL,
  last_error      VARCHAR(500) NULL,
  imported_count  INT UNSIGNED NOT NULL DEFAULT 0,
  UNIQUE KEY uq_feed (name)
) ENGINE=InnoDB;

-- ─────────────────────────────────────────────────────────────
-- 12. Audit chain & system health
-- ─────────────────────────────────────────────────────────────
CREATE TABLE audit_log (
  id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  actor_id    BIGINT UNSIGNED NULL,
  action      VARCHAR(80) NOT NULL,          -- 'alert.resolve','key.rotate'
  entity_type VARCHAR(40) NULL,
  entity_ref  VARCHAR(64) NULL,
  metadata    JSON NULL,
  prev_hash   CHAR(64) NOT NULL,             -- genesis row: 64 zeros
  hash        CHAR(64) NOT NULL,             -- SHA256(prev_hash || canonical(row))
  created_at  DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  CONSTRAINT fk_audit_actor FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE SET NULL,
  UNIQUE KEY uq_audit_hash (hash),
  KEY idx_audit_time (created_at)
) ENGINE=InnoDB;

CREATE TABLE service_health (
  id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  service      VARCHAR(60) NOT NULL,
  status       ENUM('ok','warn','down') NOT NULL DEFAULT 'ok',
  detail       VARCHAR(120) NULL,
  latency_ms   INT UNSIGNED NULL,
  checked_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_health_service_time (service, checked_at)
) ENGINE=InnoDB;

CREATE TABLE settings (
  k          VARCHAR(80) PRIMARY KEY,
  v          VARCHAR(500) NOT NULL,
  updated_by BIGINT UNSIGNED NULL,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT fk_set_user FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;


-- ─────────────────────────────────────────────────────────────
-- 13. Passwordless sign-in (email OTP) + brute-force protection
--     Codes are never stored in the clear: only a peppered SHA-256 digest.
--     SMS is deliberately absent — no SMS gateway offers a free tier, so
--     phone sign-in stays disabled until you add a paid provider.
-- ─────────────────────────────────────────────────────────────
CREATE TABLE login_codes (
  id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  channel      ENUM('email','sms','totp') NOT NULL DEFAULT 'email',
  target_bidx  CHAR(64) NOT NULL,          -- blind index of the email/phone
  code_hash    CHAR(64) NOT NULL,          -- SHA256(pepper || code)
  purpose      ENUM('signin','mfa','enrol','reset') NOT NULL DEFAULT 'signin',
  attempts     TINYINT UNSIGNED NOT NULL DEFAULT 0,
  max_attempts TINYINT UNSIGNED NOT NULL DEFAULT 5,
  consumed_at  DATETIME NULL,
  expires_at   DATETIME NOT NULL,          -- issue time + 10 minutes
  request_ip   VARCHAR(45) NULL,
  created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_lc_target (target_bidx, purpose, expires_at),
  KEY idx_lc_expiry (expires_at)
) ENGINE=InnoDB;

CREATE TABLE login_attempts (
  id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  target_bidx CHAR(64) NOT NULL,
  ip          VARCHAR(45) NULL,
  outcome     ENUM('code_sent','code_ok','code_bad','code_expired','rate_limited','password_bad','locked') NOT NULL,
  user_agent  VARCHAR(255) NULL,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_la_target_time (target_bidx, created_at),
  KEY idx_la_ip_time (ip, created_at)
) ENGINE=InnoDB;

-- Rate limit check before issuing a new code (3 per 15 min per address):
--   SELECT COUNT(*) FROM login_attempts
--   WHERE target_bidx = ? AND outcome='code_sent'
--     AND created_at >= NOW() - INTERVAL 15 MINUTE;

-- Verify (single-use, expiry- and attempt-bounded):
--   SELECT id FROM login_codes
--   WHERE target_bidx = ? AND purpose='signin' AND consumed_at IS NULL
--     AND expires_at > NOW() AND attempts < max_attempts
--     AND code_hash = SHA2(CONCAT(?, ?), 256)          -- pepper, code
--   ORDER BY id DESC LIMIT 1;
--   UPDATE login_codes SET consumed_at = NOW() WHERE id = ?;

-- Housekeeping (run nightly):
--   DELETE FROM login_codes  WHERE expires_at < NOW() - INTERVAL 1 DAY;
--   DELETE FROM login_attempts WHERE created_at < NOW() - INTERVAL 90 DAY;

-- ============================================================================
-- Reference seed
-- ============================================================================
INSERT INTO mitre_techniques (id, parent_id, name, tactic) VALUES
 ('T1566',NULL,'Phishing','Initial Access'),
 ('T1190',NULL,'Exploit Public-Facing Application','Initial Access'),
 ('T1078',NULL,'Valid Accounts','Initial Access'),
 ('T1059',NULL,'Command and Scripting Interpreter','Execution'),
 ('T1059.001','T1059','PowerShell','Execution'),
 ('T1204',NULL,'User Execution','Execution'),
 ('T1547',NULL,'Boot or Logon Autostart Execution','Persistence'),
 ('T1053',NULL,'Scheduled Task/Job','Persistence'),
 ('T1071',NULL,'Application Layer Protocol','Command and Control'),
 ('T1071.001','T1071','Web Protocols','Command and Control'),
 ('T1071.004','T1071','DNS','Command and Control'),
 ('T1090',NULL,'Proxy','Command and Control'),
 ('T1041',NULL,'Exfiltration Over C2 Channel','Exfiltration'),
 ('T1567',NULL,'Exfiltration Over Web Service','Exfiltration'),
 ('T1110',NULL,'Brute Force','Credential Access') AS new
ON DUPLICATE KEY UPDATE name=new.name, tactic=new.tactic;

INSERT INTO feed_connectors (name,status,sync_interval_min) VALUES
 ('URLhaus','not_configured',15),('ThreatFox','not_configured',15),
 ('AbuseIPDB','not_configured',30),('CISA KEV','not_configured',360),
 ('AlienVault OTX','not_configured',60),('MISP','not_configured',60) AS new
ON DUPLICATE KEY UPDATE status=feed_connectors.status;

INSERT INTO settings (k,v) VALUES
 ('mfa.required.admin','true'),('mfa.required.analyst','true'),
 ('session.ttl_minutes','15'),('apikeys.enabled','false'),
 ('confidence.decay_days','30'),('anomaly.contamination','0.02') AS new
ON DUPLICATE KEY UPDATE v=new.v;

-- ============================================================================
-- Queries the console runs (one per screen — drop these into the API layer)
-- ============================================================================

-- Overview · metric strip -----------------------------------------------------
-- SELECT
--   SUM(status IN ('open','triaged','investigating'))                        AS open_alerts,
--   SUM(severity='critical' AND status NOT IN ('resolved','false_positive')) AS critical_open,
--   SUM(created_at >= NOW() - INTERVAL 24 HOUR)                              AS alerts_24h
-- FROM alerts;

-- Overview · detection volume, 24 buckets ------------------------------------
-- SELECT FLOOR(TIMESTAMPDIFF(MINUTE, NOW() - INTERVAL 24 HOUR, created_at)/60) AS bucket,
--        severity, COUNT(*) AS n
-- FROM alerts WHERE created_at >= NOW() - INTERVAL 24 HOUR
-- GROUP BY bucket, severity ORDER BY bucket;

-- Overview · assets under pressure -------------------------------------------
-- SELECT e.name, e.risk_score, COUNT(a.id) AS alerts
-- FROM entities e JOIN alerts a ON a.entity_id = e.id
-- WHERE e.kind='host' AND a.created_at >= NOW() - INTERVAL 24 HOUR
-- GROUP BY e.id ORDER BY alerts DESC LIMIT 6;

-- ATT&CK matrix ---------------------------------------------------------------
-- SELECT mt.tactic, mt.id, mt.name, COUNT(at.alert_id) AS detections
-- FROM mitre_techniques mt
-- LEFT JOIN alert_techniques at ON at.technique_id = mt.id
-- LEFT JOIN alerts a ON a.id = at.alert_id AND a.created_at >= NOW() - INTERVAL 24 HOUR
-- GROUP BY mt.id ORDER BY mt.tactic, mt.id;

-- Alert flyout (detail + reasons + techniques) --------------------------------
-- SELECT a.*, r.name AS rule_name FROM alerts a LEFT JOIN rules r ON r.id=a.rule_id
-- WHERE a.public_id = ?;
-- SELECT reason, signal_name, value FROM alert_reasons WHERE alert_id = ? ORDER BY ordinal;

-- Indicator lookup by value (never decrypts to search) ------------------------
-- SELECT * FROM indicators WHERE type = ? AND value_bidx = HEX(?);   -- pass HMAC(key, needle)

-- Investigation graph, 1 hop from an entity -----------------------------------
-- SELECT e2.id, e2.kind, e2.name, e2.risk_score, ee.relation, ee.observations
-- FROM entity_edges ee
-- JOIN entities e1 ON e1.id = ee.src_id
-- JOIN entities e2 ON e2.id = ee.dst_id
-- WHERE e1.name_bidx = ?                       -- blind index of 'DESKTOP-04'
-- UNION
-- SELECT e1.id, e1.kind, e1.name, e1.risk_score, ee.relation, ee.observations
-- FROM entity_edges ee
-- JOIN entities e2 ON e2.id = ee.dst_id
-- JOIN entities e1 ON e1.id = ee.src_id
-- WHERE e2.name_bidx = ?;

-- Threat hunting (the Query Lab compiles to something like this) --------------
-- SELECT ev.occurred_at, en.name AS asset, ev.destination_ip, ev.bytes_out, ans.score
-- FROM events ev
-- LEFT JOIN entities en ON en.id = ev.entity_id
-- LEFT JOIN anomaly_scores ans ON ans.event_id = ev.id
-- WHERE ev.source_ip = ? AND ev.bytes_out > 10000000 AND ans.score > 0.8
--   AND ev.occurred_at >= NOW() - INTERVAL 7 DAY
-- ORDER BY ans.score DESC LIMIT 200;

-- Audit chain verification ----------------------------------------------------
-- Walk audit_log ORDER BY id, recomputing each hash from prev_hash plus the
-- canonical serialisation your app uses, and confirm every row's prev_hash
-- equals the previous row's hash. Do this in application code — MySQL's SHA2()
-- cannot reproduce the canonical form on its own.


-- ============================================================================
-- REPAIR BLOCK — only if you kept the half-built schema instead of dropping it
-- Run these, then re-run everything from CREATE TABLE alert_reasons onward.
-- ============================================================================
-- ALTER TABLE alert_reasons          CHANGE `signal` signal_name VARCHAR(80)  NULL;
-- ALTER TABLE investigation_timeline CHANGE `signal` signal_name VARCHAR(120) NULL;
-- SELECT table_name FROM information_schema.tables WHERE table_schema='skyrecon';
--   -- expect 33 tables when the schema is complete
