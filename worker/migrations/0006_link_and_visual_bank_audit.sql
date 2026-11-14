-- ============================================================================
-- MIGRACIÓN 0006: Verificación Funcional de Enlaces y Comparación Visual Bancaria
-- Idempotente para ejecución continua en Cloudflare D1 y simulador Edge local
-- ============================================================================

CREATE TABLE IF NOT EXISTS scan_deep_audits (
    scan_id TEXT PRIMARY KEY NOT NULL,
    link_functionality_json TEXT NOT NULL,
    visual_brand_audit_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scan_deep_audits_created ON scan_deep_audits(created_at DESC);
