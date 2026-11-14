-- ============================================================================
-- MIGRACIÓN 0007: Expediente Forense Profundo Anti-Phishing
-- (Hosting/ASN/DNS, Registros WHOIS/RDAP, Destinos/Repositorios y Consultas cURL)
-- ============================================================================

CREATE TABLE IF NOT EXISTS scan_forensic_dossiers (
    scan_id TEXT PRIMARY KEY NOT NULL,
    phishing_forensics_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scan_forensic_dossiers_created ON scan_forensic_dossiers(created_at DESC);
