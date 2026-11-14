-- ============================================================================
-- MÓDULO INTEGRAL DE PROTECCIÓN PARA PERSONAS MAYORES ("MODO ADULTO MAYOR")
-- Ángel Guardián, Directorio Blanco Oficial y Alertas Familiares
-- Versión: 2.6.0
-- ============================================================================

PRAGMA foreign_keys = ON;

-- ----------------------------------------------------------------------------
-- 1. TABLA: guardian_consultations (Red de Apoyo Familiar "Ángel Guardián")
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS guardian_consultations (
    id TEXT PRIMARY KEY NOT NULL,                      -- ULID: grd_...
    token TEXT NOT NULL UNIQUE,                        -- Código único de consulta familiar
    scan_id TEXT,                                      -- FK opcional a scans(id)
    senior_name TEXT NOT NULL DEFAULT 'Familiar Mayor',
    guardian_name TEXT NOT NULL,
    guardian_phone TEXT NOT NULL DEFAULT '',
    alert_mode TEXT NOT NULL DEFAULT 'ASK_GUARDIAN' CHECK (
        alert_mode IN ('ASK_GUARDIAN', 'AUTO_CRITICAL_ALERT')
    ),
    target_url TEXT NOT NULL DEFAULT '',
    message_excerpt TEXT NOT NULL DEFAULT '',
    risk_score INTEGER NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    risk_level TEXT NOT NULL DEFAULT 'WARNING' CHECK (
        risk_level IN ('SAFE', 'WARNING', 'CRITICAL')
    ),
    guardian_decision TEXT NOT NULL DEFAULT 'PENDING' CHECK (
        guardian_decision IN ('PENDING', 'SAFE_APPROVED', 'DANGER_DELETE')
    ),
    guardian_note TEXT NOT NULL DEFAULT '',
    responded_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_guardian_token ON guardian_consultations(token);
CREATE INDEX IF NOT EXISTS idx_guardian_created ON guardian_consultations(created_at DESC);

-- ----------------------------------------------------------------------------
-- 2. TABLA: verified_directory (Directorio Blanco Oficial de Bancos y Entes)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS verified_directory (
    id TEXT PRIMARY KEY NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    entity_name TEXT NOT NULL,
    category TEXT NOT NULL CHECK (
        category IN ('BANCO', 'ORGANISMO_PUBLICO', 'ENVIOS', 'EMERGENCIA')
    ),
    official_domain TEXT NOT NULL,
    official_url TEXT NOT NULL,
    emergency_phone TEXT NOT NULL,
    customer_phone TEXT NOT NULL,
    never_asks_notice TEXT NOT NULL,
    search_keywords TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_verified_directory_cat ON verified_directory(category);

-- ----------------------------------------------------------------------------
-- 3. SEMILLAS OFICIALES VERIFICADAS (BANCOS, ORGANISMOS PÚBLICOS Y ENVÍOS)
-- ----------------------------------------------------------------------------
INSERT OR IGNORE INTO verified_directory (
    id, slug, entity_name, category, official_domain, official_url,
    emergency_phone, customer_phone, never_asks_notice, search_keywords
) VALUES
(
    'dir_banesco', 'banesco', 'Banesco Banco Universal', 'BANCO',
    'banesco.com', 'https://www.banesco.com',
    '0500-2263726', '0212-5011111',
    'Banesco NUNCA envía enlaces por WhatsApp ni solicita claves dinámicas o coordenadas por mensaje.',
    'banesco online pago movil bloqueo tarjeta banco'
),
(
    'dir_bdv', 'banco-de-venezuela', 'Banco de Venezuela (BDV)', 'BANCO',
    'bancodevenezuela.com', 'https://www.bancodevenezuela.com',
    '0500-6425283', '0212-4092668',
    'BDV jamás pide usuario, contraseña ni códigos SMS AMI por WhatsApp o llamadas entrantes.',
    'bdv banco de venezuela bdv en linea clave ami tarjeta'
),
(
    'dir_mercantil', 'mercantil', 'Mercantil Banco Universal', 'BANCO',
    'mercantilbanco.com', 'https://www.mercantilbanco.com',
    '0212-5032522', '0212-5032424',
    'Mercantil nunca te pedirá claves temporales ni actualizar datos mediante enlaces acortados.',
    'mercantil tpagar personas bloqueo tarjeta banco'
),
(
    'dir_provincial', 'provincial', 'BBVA Provincial', 'BANCO',
    'provincial.com', 'https://www.provincial.com',
    '0500-5087432', '0212-5045111',
    'BBVA Provincial jamás solicita tokens digitales ni claves de cajero por SMS o redes sociales.',
    'provincial bbva dinero rapido bloqueo banco'
),
(
    'dir_bnc', 'bnc', 'Banco Nacional de Crédito (BNC)', 'BANCO',
    'bncenlinea.com', 'https://www.bncenlinea.com',
    '0500-2625000', '0212-5975000',
    'El BNC nunca solicita validación de cuentas ni códigos de seguridad fuera de su portal oficial.',
    'bnc banco nacional de credito bncnet bingo clave'
),
(
    'dir_bancamiga', 'bancamiga', 'Bancamiga Banco Universal', 'BANCO',
    'bancamiga.com', 'https://www.bancamiga.com',
    '0500-8822622', '0212-9586000',
    'Bancamiga nunca contacta por números personales de WhatsApp para desbloquear cuentas.',
    'bancamiga tarjeta mastercard bloqueo banco'
),
(
    'dir_ivss', 'ivss', 'IVSS — Instituto Venezolano de los Seguros Sociales (Pensiones)', 'ORGANISMO_PUBLICO',
    'ivss.gob.ve', 'https://www.ivss.gob.ve',
    '0212-8011050', '0212-8011050',
    'El IVSS NUNCA cobra tarifas ni envía enlaces que vencen en 10 minutos para cobrar la pensión.',
    'ivss pension pensionados seguro social abuelos'
),
(
    'dir_patria', 'patria', 'Plataforma Sistema Patria', 'ORGANISMO_PUBLICO',
    'patria.org.ve', 'https://www.patria.org.ve',
    '3532', '3532',
    'Patria solo notifica desde los números cortos oficiales 3532, 67373 y 3777; nunca por WhatsApp.',
    'patria bono subsidio monedero adultos mayores'
),
(
    'dir_saime', 'saime', 'SAIME — Identificación, Migración y Extranjería', 'ORGANISMO_PUBLICO',
    'saime.gob.ve', 'https://www.saime.gob.ve',
    '0800-7246300', '0800-7246300',
    'El SAIME no gestiona citas, prórrogas ni cobros mediante gestores en WhatsApp o Telegram.',
    'saime cedula pasaporte cita identidad'
),
(
    'dir_seniat', 'seniat', 'SENIAT — Administración Aduanera y Tributaria', 'ORGANISMO_PUBLICO',
    'seniat.gob.ve', 'https://www.seniat.gob.ve',
    '0800-0736428', '0800-0736428',
    'El SENIAT jamás exige pagos de multas urgentes a cuentas personales ni envía archivos adjuntos ejecutables.',
    'seniat rif impuesto aduana declaracion'
),
(
    'dir_corpoelec', 'corpoelec', 'CORPOELEC — Energía Eléctrica', 'ORGANISMO_PUBLICO',
    'corpoelec.gob.ve', 'https://www.corpoelec.gob.ve',
    '0212-5020000', '0500-5020000',
    'Corpoelec no envía códigos QR informales de corte inmediato pidiendo transferencias a terceros.',
    'corpoelec luz electricidad factura recibo corte'
),
(
    'dir_cicpc', 'cicpc', 'C.I.C.P.C — División de Investigaciones de Delitos Informáticos', 'EMERGENCIA',
    'cicpc.gob.ve', 'https://www.cicpc.gob.ve',
    '0800-2427224', '0800-2427224',
    'Canal institucional oficial para denunciar estafas digitales, suplantación de identidad y extorsión.',
    'cicpc denuncia emergencia policia delitos informaticos estafa'
),
(
    'dir_zoom', 'zoom', 'Grupo ZOOM Envíos Internacionales y Nacionales', 'ENVIOS',
    'zoom.red', 'https://zoom.red',
    '0501-9666000', '0212-2046800',
    'ZOOM nunca envía SMS desde líneas prepago exigiendo pagos de aduana en enlaces extraños (.xyz / .top).',
    'zoom paquete envio encomienda casillero guia'
),
(
    'dir_mrw', 'mrw', 'MRW Mensajería y Encomiendas', 'ENVIOS',
    'mrwve.com', 'https://mrwve.com',
    '0800-3040000', '0212-9551800',
    'MRW solo informa estatus de guías en su web oficial mrwve.com; nunca cobra recargos sorpresivos por SMS.',
    'mrw paquete envio agencia encomienda'
),
(
    'dir_tealca', 'tealca', 'TEALCA Transferencias y Encomiendas', 'ENVIOS',
    'tealca.com', 'https://www.tealca.com',
    '0212-7615239', '0212-7615239',
    'TEALCA jamás solicita datos de tarjetas de crédito por mensajes de texto para liberar paquetes.',
    'tealca paquete envio carga encomienda'
);

-- Consulta familiar semilla de demostración para verificación inmediata
INSERT OR IGNORE INTO guardian_consultations (
    id, token, scan_id, senior_name, guardian_name, guardian_phone,
    alert_mode, target_url, message_excerpt, risk_score, risk_level,
    guardian_decision, guardian_note
) VALUES (
    'grd_01J9SEEDGUARDIANDEMO0001',
    'GRD2026DEMO1',
    'scn_01J9SEED01PAQUETEXYZ000001',
    'Mamá Carmen',
    'Hijo Carlos',
    '+584125550199',
    'ASK_GUARDIAN',
    'http://entrega-paquete-pendiente.ejemplo.xyz/pago',
    'Mensaje SMS: Tu paquete está retenido, paga la tarifa hoy mismo en entrega-paquete-pendiente.ejemplo.xyz/pago',
    92,
    'CRITICAL',
    'PENDING',
    ''
);
