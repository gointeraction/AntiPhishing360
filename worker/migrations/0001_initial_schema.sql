-- ============================================================================
-- ESQUEMA DE BASE DE DATOS: Detector360 Web Comercial & Motor Forense
-- Motor: Cloudflare D1 (SQLite)
-- Versión: 1.0.0 - Producción
-- ============================================================================

PRAGMA foreign_keys = ON;

-- ----------------------------------------------------------------------------
-- 1. TABLA: users (Ciudadanos y clientes comerciales)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY NOT NULL,                      -- ULID: usr_...
    alias TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,                       -- PBKDF2-HMAC-SHA512
    plan_tier TEXT NOT NULL DEFAULT 'citizen_free' CHECK (
        plan_tier IN ('citizen_free', 'family_shield', 'verified_merchant')
    ),
    is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_plan_tier ON users(plan_tier);

-- ----------------------------------------------------------------------------
-- 2. TABLA: refresh_tokens (Sesiones seguras JWT)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id TEXT PRIMARY KEY NOT NULL,                      -- ULID: rtk_...
    user_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    user_agent TEXT,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);

-- ----------------------------------------------------------------------------
-- 3. TABLA: scans (Auditorías ejecutadas desde portada o PWA)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY NOT NULL,                      -- ULID: scn_...
    user_id TEXT,                                      -- NULL si fue escaneo anónimo en portada
    target_url TEXT NOT NULL,
    final_url TEXT NOT NULL,
    target_domain TEXT NOT NULL,
    protocol TEXT NOT NULL CHECK (protocol IN ('http', 'https')),
    http_status_code INTEGER NOT NULL,
    redirect_count INTEGER NOT NULL DEFAULT 0 CHECK (redirect_count >= 0),
    has_hsts INTEGER NOT NULL DEFAULT 0 CHECK (has_hsts IN (0, 1)),
    has_csp INTEGER NOT NULL DEFAULT 0 CHECK (has_csp IN (0, 1)),
    has_x_frame_options INTEGER NOT NULL DEFAULT 0 CHECK (has_x_frame_options IN (0, 1)),
    risk_score INTEGER NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    risk_level TEXT NOT NULL CHECK (risk_level IN ('SAFE', 'WARNING', 'CRITICAL')),
    citizen_verdict_title TEXT NOT NULL,
    citizen_verdict_summary TEXT NOT NULL,
    action_steps_json TEXT NOT NULL,                   -- Pasos prácticos para usuario no experto
    source_preview_json TEXT NOT NULL,                 -- Fragmentos de líneas alrededor de hallazgos
    r2_snapshot_key TEXT,                              -- Evidencia HTML sanitizada en R2
    integrity_sha256 TEXT NOT NULL,                    -- Firma SHA-256 de integridad
    scan_duration_ms INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_scans_user_created ON scans(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_domain_created ON scans(target_domain, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_risk_level ON scans(risk_level);

-- ----------------------------------------------------------------------------
-- 4. TABLA: scan_findings (Infracciones exactas detectadas en el código)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_findings (
    id TEXT PRIMARY KEY NOT NULL,                      -- ULID: fnd_...
    scan_id TEXT NOT NULL,
    rule_code TEXT NOT NULL,
    category TEXT NOT NULL CHECK (category IN ('TRANSPORT', 'DOM_FORM', 'DOM_INPUT', 'JS_SCRIPT')),
    severity TEXT NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    line_number INTEGER NOT NULL CHECK (line_number >= 0),
    column_number INTEGER NOT NULL DEFAULT 1 CHECK (column_number >= 1),
    dom_selector TEXT NOT NULL,
    citizen_explanation TEXT NOT NULL,                 -- Lenguaje claro para no expertos
    technical_detail TEXT NOT NULL,                    -- Detalle forense
    code_snippet TEXT NOT NULL,                        -- Línea exacta infractora
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON scan_findings(scan_id);

-- ----------------------------------------------------------------------------
-- 5. TABLA: community_alerts (Muro público de amenazas en portada)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS community_alerts (
    id TEXT PRIMARY KEY NOT NULL,                      -- ULID: alt_...
    scan_id TEXT NOT NULL,
    reported_by_user_id TEXT NOT NULL,
    target_domain TEXT NOT NULL,
    risk_score INTEGER NOT NULL CHECK (risk_score >= 70),
    threat_category_label TEXT NOT NULL,               -- Ej: "Robo de Tarjeta sin Cifrado HTTP"
    channel_received TEXT NOT NULL DEFAULT 'whatsapp' CHECK (
        channel_received IN ('whatsapp', 'telegram', 'sms', 'email', 'social', 'web')
    ),
    status TEXT NOT NULL DEFAULT 'published' CHECK (status IN ('published', 'under_review', 'removed')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (reported_by_user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_community_alerts_status_created ON community_alerts(status, created_at DESC);

-- ----------------------------------------------------------------------------
-- 6. TABLA: commercial_leads (Solicitudes de planes Familia y Comercio)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS commercial_leads (
    id TEXT PRIMARY KEY NOT NULL,                      -- ULID: led_...
    user_id TEXT,                                      -- Opcional si ya tiene cuenta gratuita
    plan_selected TEXT NOT NULL CHECK (
        plan_selected IN ('family_shield', 'verified_merchant')
    ),
    full_name TEXT NOT NULL,
    email TEXT NOT NULL,
    phone_or_domain TEXT NOT NULL,
    notes TEXT,
    status TEXT NOT NULL DEFAULT 'pending_activation' CHECK (
        status IN ('pending_activation', 'contacted', 'active', 'cancelled')
    ),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_commercial_leads_status ON commercial_leads(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_commercial_leads_email ON commercial_leads(email);

-- ----------------------------------------------------------------------------
-- 7. TABLA: clarity_feedback (KPI Encuesta 1 clic de comprensión ciudadana)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS clarity_feedback (
    id TEXT PRIMARY KEY NOT NULL,
    scan_id TEXT NOT NULL,
    is_clear INTEGER NOT NULL CHECK (is_clear IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_clarity_feedback_scan ON clarity_feedback(scan_id);
