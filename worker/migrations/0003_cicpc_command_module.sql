-- ============================================================================
-- MÓDULO DE COMANDO E INTELIGENCIA ESTRATÉGICA C.I.C.P.C
-- División de Investigaciones de Delitos Informáticos (DIDI)
-- Versión: 2.4.0 - Acceso Restringido con Claves de Seguridad
-- ============================================================================

PRAGMA foreign_keys = ON;

-- ----------------------------------------------------------------------------
-- 1. TABLA: cicpc_officers (Funcionarios y Analistas Autorizados DIDI-CICPC)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cicpc_officers (
    id TEXT PRIMARY KEY NOT NULL,                      -- ULID: ofc_...
    badge_id TEXT NOT NULL UNIQUE,                     -- Credencial oficial: CICPC-DIDI-2429
    full_name TEXT NOT NULL,
    rank_title TEXT NOT NULL,
    password_hash TEXT NOT NULL,                       -- PBKDF2-HMAC-SHA512 (210k iteraciones)
    security_key_sha256 TEXT NOT NULL,                 -- SHA-256 de la Clave Maestra Institucional
    role TEXT NOT NULL DEFAULT 'FORENSIC_ANALYST' CHECK (
        role IN ('COMMANDER', 'FORENSIC_ANALYST')
    ),
    is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    last_login_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_cicpc_officers_badge ON cicpc_officers(badge_id);

-- ----------------------------------------------------------------------------
-- 2. TABLA: cicpc_cases (Bandeja Central de Denuncias y Notificaciones Forenses)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cicpc_cases (
    id TEXT PRIMARY KEY NOT NULL,                      -- ULID: cas_...
    case_number TEXT NOT NULL UNIQUE,                  -- Ej: EXP-DIDI-2026-0101
    scan_id TEXT NOT NULL,
    reported_by_user_id TEXT,
    source_type TEXT NOT NULL DEFAULT 'CITIZEN_COMPLAINT' CHECK (
        source_type IN ('CITIZEN_COMPLAINT', 'COMMUNITY_ALERT', 'AUTO_CRITICAL_DETECTION')
    ),
    target_url TEXT NOT NULL,
    target_domain TEXT NOT NULL,
    risk_score INTEGER NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    risk_level TEXT NOT NULL CHECK (risk_level IN ('SAFE', 'WARNING', 'CRITICAL')),
    channel_received TEXT NOT NULL DEFAULT 'whatsapp' CHECK (
        channel_received IN ('whatsapp', 'telegram', 'sms', 'email', 'social', 'web')
    ),
    impersonated_entity TEXT NOT NULL DEFAULT 'No especificada',
    suspect_contact TEXT NOT NULL DEFAULT '',
    incident_impact TEXT NOT NULL DEFAULT 'PREVENTIVE' CHECK (
        incident_impact IN ('PREVENTIVE', 'CREDENTIALS_EXPOSED', 'FINANCIAL_LOSS')
    ),
    citizen_statement TEXT NOT NULL DEFAULT '',
    reporter_contact TEXT NOT NULL DEFAULT '',
    priority TEXT NOT NULL DEFAULT 'HIGH' CHECK (
        priority IN ('URGENT', 'HIGH', 'NORMAL')
    ),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (
        status IN ('pending', 'in_analysis', 'strategic_action', 'mitigated', 'archived')
    ),
    strategic_action_type TEXT NOT NULL DEFAULT 'NONE' CHECK (
        strategic_action_type IN (
            'NONE',
            'ISP_DNS_BLOCK_REQUEST',
            'REGISTRAR_TAKEDOWN',
            'BANKING_FRAUD_ALERT',
            'TRACE_EXFILTRATION_SERVER',
            'PUBLIC_PREVENTION_BULLETIN',
            'FIELD_INVESTIGATION_OPENED'
        )
    ),
    expert_notes TEXT NOT NULL DEFAULT '',
    reviewed_by_badge TEXT,
    reviewed_by_name TEXT,
    reviewed_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (reported_by_user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_cicpc_cases_status_priority ON cicpc_cases(status, priority, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_cicpc_cases_domain ON cicpc_cases(target_domain);
CREATE INDEX IF NOT EXISTS idx_cicpc_cases_scan_id ON cicpc_cases(scan_id);

-- ----------------------------------------------------------------------------
-- 3. TABLA: cicpc_audit_logs (Cadena de Custodia y Bitácora Inmutable)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cicpc_audit_logs (
    id TEXT PRIMARY KEY NOT NULL,                      -- ULID: aud_...
    officer_badge TEXT NOT NULL,
    officer_name TEXT NOT NULL,
    action_code TEXT NOT NULL,
    case_id TEXT,
    detail TEXT NOT NULL,
    client_ip TEXT NOT NULL DEFAULT '0.0.0.0',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_cicpc_audit_created ON cicpc_audit_logs(created_at DESC);

-- ----------------------------------------------------------------------------
-- 4. FUNCIONARIOS AUTORIZADOS POR DEFECTO (CREDENCIALES CRIPTOGRÁFICAS)
--    Clave Maestra Institucional: DIDI-360-CLAVE-SEGURIDAD-2026
--    Funcionario 1: CICPC-DIDI-2429 / Cicpc*Delitos2026!
--    Funcionario 2: CICPC-DIDI-1084 / Analista*Forense360!
-- ----------------------------------------------------------------------------
INSERT OR IGNORE INTO cicpc_officers (
    id, badge_id, full_name, rank_title, password_hash, security_key_sha256, role, is_active
) VALUES
(
    'ofc_01J9CICPC2429COMMANDER0001',
    'CICPC-DIDI-2429',
    'Comisario Jefe R. Mendoza',
    'Jefe de Operaciones Estratégicas — Delitos Informáticos',
    'pbkdf2_sha512$210000$8fe9cd34d3bd0a7fc5893efdc4dea4d2$1fe2a5dc3cc4cfbb350bf0784b6263088e015f10db059b6d64fa8e16c9c68ebcc01460607a9341c0a556d7a9b117f64dc348b134de3d85738785c657ddb648a9',
    'f0dcd34543cf9424ad49ae5cf905dd1f66ed8f25ee538f947c102a15f66d7eaf',
    'COMMANDER',
    1
),
(
    'ofc_01J9CICPC1084ANALYST000002',
    'CICPC-DIDI-1084',
    'Inspectora V. Castellanos',
    'Analista Experta en Evidencia Forense Web',
    'pbkdf2_sha512$210000$cd5984e0074f9ff8848359ad15c6188d$e82c9f82aa7e5e38195a919480e71725188f1b222d5688f9d9de6629ff383bed566317668d581fd39780dfadb7a1e7acbd93efca9db80c6ad32f0aebd9990ef1',
    'f0dcd34543cf9424ad49ae5cf905dd1f66ed8f25ee538f947c102a15f66d7eaf',
    'FORENSIC_ANALYST',
    1
);

-- ----------------------------------------------------------------------------
-- 5. CASOS INICIALES VINCULADOS A AUDITORÍAS FORENSES SEMILLA
-- ----------------------------------------------------------------------------
INSERT OR IGNORE INTO cicpc_cases (
    id, case_number, scan_id, reported_by_user_id, source_type,
    target_url, target_domain, risk_score, risk_level, channel_received,
    impersonated_entity, suspect_contact, incident_impact, citizen_statement,
    reporter_contact, priority, status, strategic_action_type, expert_notes,
    reviewed_by_badge, reviewed_by_name, reviewed_at, created_at, updated_at
) VALUES
(
    'cas_01J9SEED01BANESCO2429A',
    'EXP-DIDI-2026-0101',
    'scn_01J9SEED02BANESCOVERIF0002',
    'usr_01J9X00000SYSTEMGUARD36000',
    'CITIZEN_COMPLAINT',
    'http://banesco-verificacion-segura.ejemplo.xyz/login',
    'banesco-verificacion-segura.ejemplo.xyz',
    98,
    'CRITICAL',
    'whatsapp',
    'Banca Nacional (Clonación Banesco)',
    '+58 412-9084412',
    'CREDENTIALS_EXPOSED',
    'Recibí un mensaje urgente por WhatsApp indicando bloqueo preventivo de cuenta. Alcancé a abrir el enlace y luego lo verifiqué en Detector360.',
    'ciudadano.afectado@correo.ve',
    'URGENT',
    'in_analysis',
    'BANKING_FRAUD_ALERT',
    'Confirmada exfiltración cruzada hacia servidor externo robo-datos.xyz y listener de teclado activo. Se articula alerta interbancaria preventiva.',
    'CICPC-DIDI-1084',
    'Inspectora V. Castellanos',
    strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-18 minutes'),
    strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-27 minutes'),
    strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-18 minutes')
),
(
    'cas_01J9SEED02PAQUETEXYZ02',
    'EXP-DIDI-2026-0102',
    'scn_01J9SEED01PAQUETEXYZ000001',
    'usr_01J9X00000SYSTEMGUARD36000',
    'CITIZEN_COMPLAINT',
    'http://entrega-paquete-pendiente.ejemplo.xyz/pago',
    'entrega-paquete-pendiente.ejemplo.xyz',
    96,
    'CRITICAL',
    'sms',
    'Servicio Postal / Encomiendas Nacionales',
    'SMS Corto 78402',
    'PREVENTIVE',
    'Llegó por mensaje de texto pidiendo pagar $2.50 con tarjeta por paquete retenido en aduana. Detector360 me avisó antes de meter mi tarjeta.',
    '+58 414-5521908',
    'HIGH',
    'pending',
    'NONE',
    '',
    NULL,
    NULL,
    NULL,
    strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-10 minutes'),
    strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-10 minutes')
),
(
    'cas_01J9SEED03BONOAYUDA003',
    'EXP-DIDI-2026-0103',
    'scn_01J9SEED03BONOAYUDA2026003',
    'usr_01J9X00000SYSTEMGUARD36000',
    'COMMUNITY_ALERT',
    'http://bono-ayuda-nacional-2026.ejemplo.xyz/registro',
    'bono-ayuda-nacional-2026.ejemplo.xyz',
    91,
    'CRITICAL',
    'whatsapp',
    'Plataforma de Bonos / Ayuda Social',
    'Cadena Grupos Vecinales WhatsApp',
    'PREVENTIVE',
    'Enlace difundido masivamente en grupos comunitarios solicitando cédula y contraseña bancaria en texto plano.',
    '',
    'HIGH',
    'strategic_action',
    'ISP_DNS_BLOCK_REQUEST',
    'Campaña masiva detectada en múltiples reportes ciudadanos. Solicitado bloqueo DNS a operadoras y emisión de boletín preventivo.',
    'CICPC-DIDI-2429',
    'Comisario Jefe R. Mendoza',
    strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-32 minutes'),
    strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-45 minutes'),
    strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-32 minutes')
);

INSERT OR IGNORE INTO cicpc_audit_logs (
    id, officer_badge, officer_name, action_code, case_id, detail, client_ip, created_at
) VALUES
(
    'aud_01J9SEEDLOG00000000001',
    'CICPC-DIDI-2429',
    'Comisario Jefe R. Mendoza',
    'STRATEGIC_ACTION_EXECUTED',
    'cas_01J9SEED03BONOAYUDA003',
    'Ordenó bloqueo DNS nacional (ISP_DNS_BLOCK_REQUEST) sobre bono-ayuda-nacional-2026.ejemplo.xyz',
    '10.24.0.12',
    strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-32 minutes')
),
(
    'aud_01J9SEEDLOG00000000002',
    'CICPC-DIDI-1084',
    'Inspectora V. Castellanos',
    'CASE_REVIEWED',
    'cas_01J9SEED01BANESCO2429A',
    'Inició análisis forense y emitió alerta bancaria preventiva (BANKING_FRAUD_ALERT) para EXP-DIDI-2026-0101',
    '10.24.0.19',
    strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-18 minutes')
);
