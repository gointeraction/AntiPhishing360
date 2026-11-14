-- ============================================================================
-- ESQUEMA DE BASE DE DATOS: Detector360 (Cloudflare D1 / SQLite)
-- Versión: 1.0.0 - Producción (Normalizado 3FN)
-- ============================================================================

PRAGMA foreign_keys = ON;

-- ----------------------------------------------------------------------------
-- 1. TABLA: users (Ciudadanos registrados opcionalmente)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY NOT NULL,                      -- Formato ULID: usr_...
    alias TEXT NOT NULL,                               -- Nombre o alias ciudadano
    email TEXT NOT NULL UNIQUE,                        -- Correo electrónico normalizado en minúsculas
    password_hash TEXT NOT NULL,                       -- $pbkdf2-sha512$210000$<salt_hex>$<hash_hex>
    is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- ----------------------------------------------------------------------------
-- 2. TABLA: refresh_tokens (Control de sesiones y rotación JWT)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id TEXT PRIMARY KEY NOT NULL,                      -- Formato ULID: rtk_...
    user_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,                   -- SHA-256 del refresh token en crudo
    user_agent TEXT,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,                                   -- NULL si sigue vigente
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at);

-- ----------------------------------------------------------------------------
-- 3. TABLA: scans (Auditorías forenses de URLs ejecutadas)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY NOT NULL,                      -- Formato ULID: scn_...
    user_id TEXT,                                      -- NULL si fue escaneo anónimo
    target_url TEXT NOT NULL,
    final_url TEXT NOT NULL,
    target_domain TEXT NOT NULL,
    protocol TEXT NOT NULL CHECK (protocol IN ('http', 'https')),
    http_status_code INTEGER NOT NULL,
    redirect_count INTEGER NOT NULL DEFAULT 0 CHECK (redirect_count >= 0),
    redirect_chain_json TEXT NOT NULL DEFAULT '[]',    -- Historial de saltos 301/302 auditados
    has_hsts INTEGER NOT NULL DEFAULT 0 CHECK (has_hsts IN (0, 1)),
    has_csp INTEGER NOT NULL DEFAULT 0 CHECK (has_csp IN (0, 1)),
    has_x_frame_options INTEGER NOT NULL DEFAULT 0 CHECK (has_x_frame_options IN (0, 1)),
    risk_score INTEGER NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    risk_level TEXT NOT NULL CHECK (risk_level IN ('SAFE', 'WARNING', 'CRITICAL')),
    citizen_verdict_title TEXT NOT NULL,
    citizen_verdict_summary TEXT NOT NULL,
    source_preview_json TEXT NOT NULL,                 -- Fragmentos de líneas contextuales
    r2_snapshot_key TEXT,                              -- Clave en Cloudflare R2 si se guardó HTML
    case_note TEXT,                                    -- Nota opcional del caso forense
    integrity_sha256 TEXT NOT NULL,                    -- Hash SHA-256 verificable sobre evidence_payload
    scan_duration_ms INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_scans_user_created ON scans(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_domain_created ON scans(target_domain, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_risk_level ON scans(risk_level);

-- ----------------------------------------------------------------------------
-- 4. TABLA: scan_findings (Infracciones exactas detectadas en el código fuente)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_findings (
    id TEXT PRIMARY KEY NOT NULL,                      -- Formato ULID: fnd_...
    scan_id TEXT NOT NULL,
    rule_code TEXT NOT NULL,                           -- Ej: INSECURE_HTTP_SENSITIVE_FORM
    category TEXT NOT NULL CHECK (category IN ('TRANSPORT', 'DOM_FORM', 'DOM_INPUT', 'JS_SCRIPT')),
    severity TEXT NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    line_number INTEGER NOT NULL CHECK (line_number >= 0),
    column_number INTEGER NOT NULL DEFAULT 1 CHECK (column_number >= 1),
    dom_selector TEXT NOT NULL,                        -- Ej: form#login-form > input[name="pass"]
    citizen_explanation TEXT NOT NULL,                 -- Explicación clara para el ciudadano
    technical_detail TEXT NOT NULL,                    -- Diagnóstico técnico forense
    code_snippet TEXT NOT NULL,                        -- Línea exacta infractora del código
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON scan_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_rule_code ON scan_findings(rule_code);

-- ----------------------------------------------------------------------------
-- 5. TABLA: community_alerts (Alertas públicas de phishing reportadas)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS community_alerts (
    id TEXT PRIMARY KEY NOT NULL,                      -- Formato ULID: alt_...
    scan_id TEXT NOT NULL,
    reported_by_user_id TEXT NOT NULL,
    target_domain TEXT NOT NULL,
    risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    primary_rule_code TEXT NOT NULL,
    channel_received TEXT NOT NULL DEFAULT 'web' CHECK (
        channel_received IN ('whatsapp', 'telegram', 'sms', 'email', 'social', 'web')
    ),
    citizen_note TEXT,
    status TEXT NOT NULL DEFAULT 'published' CHECK (status IN ('published', 'under_review', 'removed')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (reported_by_user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_community_alerts_status_created ON community_alerts(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_community_alerts_domain ON community_alerts(target_domain);
