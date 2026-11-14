-- ============================================================================
-- PORTAL DE ACCESO DEL FAMILIAR ("SALA DE CUIDADO ÁNGEL GUARDIÁN")
-- Seguimiento en Tiempo Real de Novedades, Dudas y Alertas del Adulto Mayor
-- Versión: 2.8.0
-- ============================================================================

PRAGMA foreign_keys = ON;

-- ----------------------------------------------------------------------------
-- 1. TABLA: guardian_family_links (Vínculo Seguro Adulto Mayor <-> Familiar)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS guardian_family_links (
    id TEXT PRIMARY KEY NOT NULL,                      -- ULID: flk_...
    family_code TEXT NOT NULL UNIQUE,                  -- Ej: FAM-ABUELO-2026
    senior_name TEXT NOT NULL,
    senior_phone TEXT NOT NULL DEFAULT '',
    guardian_name TEXT NOT NULL,
    guardian_phone TEXT NOT NULL DEFAULT '',
    pin_hash TEXT NOT NULL,                            -- PBKDF2-HMAC-SHA512 (210k iteraciones)
    latest_family_broadcast TEXT NOT NULL DEFAULT '',  -- Mensaje calmado enviado al celular del abuelo
    broadcast_updated_at TEXT,
    last_senior_activity_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_family_links_code ON guardian_family_links(family_code);

-- ----------------------------------------------------------------------------
-- 2. TABLA: guardian_activity_feed (Bitácora de Novedades de la Persona Mayor)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS guardian_activity_feed (
    id TEXT PRIMARY KEY NOT NULL,                      -- ULID: gaf_...
    family_code TEXT NOT NULL,
    consultation_token TEXT,                           -- Vínculo opcional a guardian_consultations(token)
    scan_id TEXT,                                      -- Vínculo opcional a scans(id)
    event_type TEXT NOT NULL CHECK (
        event_type IN (
            'URL_SCAN',
            'MESSAGE_SCAN',
            'QR_SCAN',
            'ASK_GUARDIAN',
            'AUTO_CRITICAL_ALERT',
            'EMERGENCY_TRIGGERED'
        )
    ),
    target_url TEXT NOT NULL DEFAULT '',
    content_summary TEXT NOT NULL DEFAULT '',
    risk_score INTEGER NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    risk_level TEXT NOT NULL DEFAULT 'WARNING' CHECK (
        risk_level IN ('SAFE', 'WARNING', 'CRITICAL')
    ),
    family_status TEXT NOT NULL DEFAULT 'INFO' CHECK (
        family_status IN (
            'INFO',
            'PENDING',
            'SAFE_APPROVED',
            'DANGER_DELETE',
            'RESOLVED_BY_CALL'
        )
    ),
    family_note TEXT NOT NULL DEFAULT '',
    responded_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    FOREIGN KEY (family_code) REFERENCES guardian_family_links(family_code) ON DELETE CASCADE,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_guardian_feed_code_created
    ON guardian_activity_feed(family_code, created_at DESC);

-- ----------------------------------------------------------------------------
-- 3. SEMILLA DEMOSTRATIVA LISTA PARA REVISIÓN INMEDIATA (/familiar)
-- Código Familiar: FAM-ABUELO-2026 | Clave/PIN: ClaveFamiliar2026!
-- ----------------------------------------------------------------------------
INSERT OR IGNORE INTO guardian_family_links (
    id, family_code, senior_name, senior_phone, guardian_name, guardian_phone,
    pin_hash, latest_family_broadcast, broadcast_updated_at, last_senior_activity_at
) VALUES (
    'flk_01J9SEEDFAMILYABUELO0001',
    'FAM-ABUELO-2026',
    'Abuelo José Gregorio',
    '+58 414-5550101',
    'Hija Elena Rojas',
    '+58 412-5550199',
    'pbkdf2_sha512$210000$86d30f8f82477d25b090d0d6353c4b9c$598d7e4c5139adfcbff13866faa55987430e2d5347f4cd713e62a9400e2a8e0edfe432dfd442b771ec142588b32ce83e56a37aace59ad6d7ddc2fa501ecd56f9',
    'Papá, estoy pendiente desde mi panel familiar. Cualquier mensaje extraño que te llegue lo veo aquí contigo.',
    strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-25 minutes'),
    strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-4 minutes')
);

INSERT OR IGNORE INTO guardian_activity_feed (
    id, family_code, consultation_token, scan_id, event_type, target_url,
    content_summary, risk_score, risk_level, family_status, family_note, created_at
) VALUES
(
    'gaf_01J9SEEDEVENTABUELO00001',
    'FAM-ABUELO-2026',
    'GRD2026DEMO1',
    'scn_01J9SEED01PAQUETEXYZ000001',
    'ASK_GUARDIAN',
    'http://entrega-paquete-pendiente.ejemplo.xyz/pago',
    'El abuelo presionó "Preguntar a mi Hija en 1 Toque" tras recibir un SMS de supuesto paquete retenido pidiendo pago.',
    92,
    'CRITICAL',
    'PENDING',
    '',
    strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-4 minutes')
),
(
    'gaf_01J9SEEDEVENTABUELO00002',
    'FAM-ABUELO-2026',
    NULL,
    NULL,
    'AUTO_CRITICAL_ALERT',
    'http://bono-pension-activa.xyz/cobro',
    'Alerta Automática Escudo Familiar: Se detectó y frenó un mensaje de WhatsApp con falso bono de pensión que "vencía en 10 minutos".',
    95,
    'CRITICAL',
    'PENDING',
    '',
    strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-18 minutes')
),
(
    'gaf_01J9SEEDEVENTABUELO00003',
    'FAM-ABUELO-2026',
    NULL,
    NULL,
    'QR_SCAN',
    'http://recibo-luz-corte.xyz/pagar',
    'Escáner QR Anti-Quishing: Revisó un código QR sospechoso antes de abrirlo; Detector360 activó Semáforo Rojo preventivo.',
    88,
    'CRITICAL',
    'RESOLVED_BY_CALL',
    'Lo llamé por teléfono y rompió el volante falso.',
    strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-2 hours')
),
(
    'gaf_01J9SEEDEVENTABUELO00004',
    'FAM-ABUELO-2026',
    NULL,
    NULL,
    'URL_SCAN',
    'https://www.banesco.com',
    'Verificación en Directorio Blanco Oficial: Consultó el portal legítimo cifrado de su banco sin riesgos.',
    4,
    'SAFE',
    'INFO',
    '',
    strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-5 hours')
);
