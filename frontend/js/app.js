import { ApiClient } from './api-client.js';
import { ExportService } from './export-service.js';
import { ForensicViewer } from './forensic-viewer.js';
import { OfflineDb } from './offline-db.js';

const AppState = {
  user: null,
  currentScan: null,
  isOffline: !navigator.onLine
};

const PRIVATE_HOST_CLIENT_REGEX =
  /^(?:localhost|127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|169\.254\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|0\.0\.0\.0|\[::1\]|\[fe80:|\[fc00:|\[fd00:)$/i;

/**
 * Extracts the first HTTP/HTTPS URL from arbitrary shared text (WhatsApp/Telegram/SMS Share Target).
 */
function extractUrlFromSharedText(rawText) {
  if (!rawText || typeof rawText !== 'string') return null;
  const match = rawText.match(/https?:\/\/[^\s<>"'`]+/i);
  if (!match) return null;
  return match[0].replace(/[.,;:!?)]+$/, '');
}

/**
 * Client-side URL & Anti-SSRF validation (User Story 1 Criterion 4).
 */
function validateUrlClientSide(rawInput) {
  const trimmed = (rawInput || '').trim();
  if (!trimmed) {
    return { valid: false, error: 'Ingresa una dirección URL para iniciar el análisis.' };
  }

  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    return {
      valid: false,
      error: 'Formato de URL inválido. Asegúrate de incluir http:// o https:// al inicio.'
    };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return {
      valid: false,
      error: 'Protocolo no permitido. Solo se auditan enlaces web http:// y https://.'
    };
  }

  const host = parsed.hostname.toLowerCase();
  if (
    PRIVATE_HOST_CLIENT_REGEX.test(host) ||
    host.endsWith('.local') ||
    host.endsWith('.internal') ||
    !host.includes('.')
  ) {
    return {
      valid: false,
      error:
        'Seguridad Anti-SSRF: No se permite escanear direcciones IP privadas, redes locales (localhost) ni hosts internos.'
    };
  }

  return { valid: true, normalizedUrl: parsed.toString() };
}

/**
 * Partially obfuscates malicious domains in the public Community Alerts cards
 * so citizens recognize the scam domain without accidentally clicking/visiting it.
 */
function obfuscateDomainDisplay(domain) {
  if (!domain) return 'dominio-oculto';
  return domain.replace(/\./g, '[.]');
}

function showFeedback(elId, message, isError = true) {
  const box = document.getElementById(elId);
  if (!box) return;
  box.textContent = message;
  box.className = isError ? 'feedback-alert feedback-error' : 'feedback-alert feedback-success';
  box.hidden = false;
}

function hideFeedback(elId) {
  const box = document.getElementById(elId);
  if (box) {
    box.hidden = true;
    box.textContent = '';
  }
}

function updateAuthHeaderUi() {
  const guestBtn = document.getElementById('nav-auth-btn');
  const dashBtn = document.getElementById('nav-dashboard-btn');

  if (AppState.user) {
    guestBtn.hidden = true;
    dashBtn.hidden = false;
    dashBtn.textContent = `Mi Bóveda (${AppState.user.alias})`;
  } else {
    guestBtn.hidden = false;
    dashBtn.hidden = true;
  }
}

/* =========================================================================
 * SPA ROUTER & VIEW CONTROLLER
 * ========================================================================= */
const VIEW_IDS = [
  'view-home',
  'view-login',
  'view-register',
  'view-dashboard',
  'view-scan-new',
  'view-scan-detail',
  'view-how-it-works'
];

function showOnlyView(activeId) {
  for (const id of VIEW_IDS) {
    const sec = document.getElementById(id);
    if (sec) sec.hidden = id !== activeId;
  }
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

export async function navigateTo(path, pushHistory = true) {
  if (path.startsWith('/#')) {
    const hashId = path.slice(2);
    if (window.location.pathname !== '/') {
      history.pushState({}, '', '/');
    }
    showOnlyView('view-home');
    await loadCommunityAlertsFeed();
    const targetSection = document.getElementById(hashId);
    if (targetSection) targetSection.scrollIntoView({ behavior: 'smooth' });
    return;
  }

  if (pushHistory && window.location.pathname + window.location.search !== path) {
    history.pushState({}, '', path);
  }

  const parsedUrl = new URL(path, window.location.origin);
  const pathname = parsedUrl.pathname;

  // Handle Web Share Target parameters on `/` or `/index.html` or `/scan`
  const sharedCandidate =
    parsedUrl.searchParams.get('shared_url') ||
    parsedUrl.searchParams.get('url') ||
    parsedUrl.searchParams.get('text') ||
    parsedUrl.searchParams.get('title');

  if (sharedCandidate && (pathname === '/' || pathname === '/index.html' || pathname === '/scan')) {
    const cleanUrl = extractUrlFromSharedText(sharedCandidate) || sharedCandidate.trim();
    showOnlyView('view-home');
    const input = document.getElementById('home-url-input');
    if (input) input.value = cleanUrl;
    history.replaceState({}, '', '/');
    await executeForensicScan({ url: cleanUrl, sourceForm: 'home' });
    return;
  }

  if (pathname === '/login') {
    hideFeedback('login-feedback');
    showOnlyView('view-login');
    return;
  }

  if (pathname === '/register') {
    hideFeedback('register-feedback');
    showOnlyView('view-register');
    return;
  }

  if (pathname === '/how-it-works') {
    showOnlyView('view-how-it-works');
    return;
  }

  if (pathname === '/scan/new') {
    hideFeedback('adv-scan-error');
    showOnlyView('view-scan-new');
    return;
  }

  if (pathname.startsWith('/scan/')) {
    const scanId = decodeURIComponent(pathname.slice('/scan/'.length));
    showOnlyView('view-scan-detail');
    await loadAndRenderScanDetail(scanId);
    return;
  }

  if (pathname.startsWith('/dashboard')) {
    if (!AppState.user && !AppState.isOffline) {
      navigateTo('/login');
      return;
    }
    showOnlyView('view-dashboard');
    await loadDashboardData();
    return;
  }

  // Default: Landing / Scanner (`/`)
  showOnlyView('view-home');
  await loadCommunityAlertsFeed();
}

/* =========================================================================
 * FORENSIC SCAN EXECUTION & STEPPER ANIMATION
 * ========================================================================= */
function setStepperStage(stageIndex) {
  const stepper = document.getElementById('home-scan-stepper');
  const ids = ['step-connect', 'step-transport', 'step-domjs'];
  if (!stepper) return;

  if (stageIndex < 0) {
    stepper.hidden = true;
    return;
  }

  stepper.hidden = false;
  ids.forEach((id, idx) => {
    const node = document.getElementById(id);
    if (!node) return;
    node.classList.remove('active', 'done');
    if (idx < stageIndex) node.classList.add('done');
    else if (idx === stageIndex) node.classList.add('active');
  });
}

async function executeForensicScan({
  url,
  forceRefresh = false,
  saveSnapshot = false,
  userAgentProfile = 'mobile_android',
  caseNote = '',
  sourceForm = 'home'
}) {
  const errorBoxId = sourceForm === 'advanced' ? 'adv-scan-error' : 'home-scan-error';
  hideFeedback(errorBoxId);

  const check = validateUrlClientSide(url);
  if (!check.valid) {
    showFeedback(errorBoxId, check.error, true);
    return;
  }

  // Offline queueing support (User Story 4 Criterion 4)
  if (!navigator.onLine) {
    await OfflineDb.enqueueSharedUrl(check.normalizedUrl);
    showFeedback(
      errorBoxId,
      'Estás sin conexión a internet. Guardamos el enlace en la cola segura de tu dispositivo para analizarlo apenas vuelva la red.',
      false
    );
    return;
  }

  const submitBtn =
    sourceForm === 'advanced'
      ? document.getElementById('adv-submit-btn')
      : sourceForm === 'dashboard'
        ? document.getElementById('dash-quick-submit')
        : document.getElementById('home-scan-submit');

  if (submitBtn) submitBtn.disabled = true;
  if (sourceForm === 'home') setStepperStage(0);

  const t1 = setTimeout(() => {
    if (sourceForm === 'home') setStepperStage(1);
  }, 350);
  const t2 = setTimeout(() => {
    if (sourceForm === 'home') setStepperStage(2);
  }, 850);

  try {
    const res = await ApiClient.createScan({
      url: check.normalizedUrl,
      forceRefresh,
      saveSnapshot,
      userAgentProfile,
      caseNote
    });

    const reportData = res.data;
    AppState.currentScan = reportData;
    await OfflineDb.saveScan(reportData);

    clearTimeout(t1);
    clearTimeout(t2);
    setStepperStage(-1);
    if (submitBtn) submitBtn.disabled = false;

    await navigateTo(`/scan/${encodeURIComponent(reportData.scan_id)}`);
  } catch (err) {
    clearTimeout(t1);
    clearTimeout(t2);
    setStepperStage(-1);
    if (submitBtn) submitBtn.disabled = false;

    showFeedback(
      errorBoxId,
      err.message || 'No se pudo completar el análisis del enlace.',
      true
    );
  }
}

async function loadAndRenderScanDetail(scanId) {
  hideFeedback('detail-feedback');
  const mount = document.getElementById('forensic-report-mount');
  if (!mount) return;

  if (AppState.currentScan && AppState.currentScan.scan_id === scanId) {
    ForensicViewer.renderReport(mount, AppState.currentScan);
    return;
  }

  // Try local IndexedDB first for instant offline/cached rendering
  const localHit = await OfflineDb.getScan(scanId);
  if (localHit) {
    AppState.currentScan = localHit;
    ForensicViewer.renderReport(mount, localHit);
    return;
  }

  mount.replaceChildren();
  const loadingMsg = document.createElement('p');
  loadingMsg.className = 'text-muted';
  loadingMsg.textContent = 'Recuperando expediente forense desde Cloudflare D1...';
  mount.appendChild(loadingMsg);

  try {
    const res = await ApiClient.getScanById(scanId);
    AppState.currentScan = res.data;
    await OfflineDb.saveScan(res.data);
    ForensicViewer.renderReport(mount, res.data);
  } catch (err) {
    mount.replaceChildren();
    showFeedback(
      'detail-feedback',
      err.message || 'No se encontró el reporte solicitado ni en la nube ni en la memoria local.',
      true
    );
  }
}

/* =========================================================================
 * COMMUNITY ALERTS FEED
 * ========================================================================= */
const FALLBACK_SAMPLE_ALERTS = [
  {
    target_domain: 'verificacion-seguridad-banca.xyz',
    risk_score: 94,
    primary_rule: 'CROSS_DOMAIN_FORM_ACTION',
    channel_received: 'whatsapp',
    reports_count: 12,
    last_reported_at: '2026-11-13T21:40:00Z'
  },
  {
    target_domain: 'bono-subsidio-consulta.top',
    risk_score: 89,
    primary_rule: 'INSECURE_HTTP_SENSITIVE_FORM',
    channel_received: 'sms',
    reports_count: 8,
    last_reported_at: '2026-11-13T19:15:00Z'
  },
  {
    target_domain: 'soporte-tarjeta-activa.click',
    risk_score: 91,
    primary_rule: 'JS_ASYNC_EXFILTRATION',
    channel_received: 'telegram',
    reports_count: 5,
    last_reported_at: '2026-11-13T16:50:00Z'
  }
];

async function loadCommunityAlertsFeed() {
  const grid = document.getElementById('community-alerts-grid');
  if (!grid) return;

  let alerts = [];
  try {
    if (navigator.onLine) {
      const res = await ApiClient.getCommunityAlerts(6);
      alerts = res?.data?.alerts || [];
    }
  } catch {
    alerts = [];
  }

  if (alerts.length === 0) {
    alerts = FALLBACK_SAMPLE_ALERTS;
  }

  grid.replaceChildren();
  for (const item of alerts.slice(0, 6)) {
    const card = document.createElement('article');
    card.className = 'card alert-card';

    const topRow = document.createElement('div');
    topRow.style.display = 'flex';
    topRow.style.justifyContent = 'space-between';
    topRow.style.alignItems = 'center';
    topRow.style.gap = '8px';

    const badge = document.createElement('span');
    badge.className = 'badge badge-critical';
    badge.textContent = `Riesgo ${item.risk_score}/100`;

    const channelSpan = document.createElement('span');
    channelSpan.className = 'text-muted';
    channelSpan.textContent = `Vía ${(item.channel_received || 'web').toUpperCase()}`;

    topRow.append(badge, channelSpan);

    const domainEl = document.createElement('div');
    domainEl.className = 'mono';
    domainEl.style.fontWeight = '700';
    domainEl.style.wordBreak = 'break-all';
    domainEl.textContent = obfuscateDomainDisplay(item.target_domain);

    const ruleEl = document.createElement('div');
    ruleEl.className = 'badge badge-tech';
    ruleEl.style.alignSelf = 'flex-start';
    ruleEl.textContent = item.primary_rule;

    const footerMeta = document.createElement('div');
    footerMeta.className = 'text-muted';
    const dateShort = (item.last_reported_at || '').slice(0, 10);
    footerMeta.textContent = `${item.reports_count || 1} reporte(s) · Detectado: ${dateShort}`;

    card.append(topRow, domainEl, ruleEl, footerMeta);
    grid.appendChild(card);
  }
}

/* =========================================================================
 * DASHBOARD & HISTORY MANAGEMENT
 * ========================================================================= */
async function loadDashboardData() {
  const searchVal = document.getElementById('history-search-input')?.value || '';
  const riskVal = document.getElementById('history-risk-filter')?.value || '';
  const exportsCount = await OfflineDb.getExportCount();

  const kpiExports = document.getElementById('kpi-exports-count');
  if (kpiExports) kpiExports.textContent = String(exportsCount);

  if (AppState.user) {
    const profileBox = document.getElementById('profile-details-box');
    if (profileBox) {
      profileBox.textContent = `ID Ciudadano: ${AppState.user.id}\nAlias: ${AppState.user.alias}\nCorreo: ${AppState.user.email}`;
    }
  }

  let items = [];
  let totalScans = 0;
  let threatsBlocked = 0;

  try {
    if (navigator.onLine && AppState.user) {
      const res = await ApiClient.getHistory({
        page: 1,
        limit: 30,
        riskLevel: riskVal,
        search: searchVal
      });
      items = res.data.items || [];
      totalScans = res.data.stats?.total_scans ?? items.length;
      threatsBlocked = res.data.stats?.threats_blocked ?? 0;
    } else {
      throw new Error('Use local IndexedDB');
    }
  } catch {
    const localScans = await OfflineDb.listScans();
    totalScans = localScans.length;
    threatsBlocked = localScans.filter((s) => s.risk_level === 'CRITICAL').length;
    items = localScans
      .filter((s) => (!riskVal ? true : s.risk_level === riskVal))
      .filter((s) =>
        !searchVal
          ? true
          : (s.target_url || '').toLowerCase().includes(searchVal.toLowerCase())
      )
      .map((s) => ({
        scan_id: s.scan_id,
        target_url: s.target_url,
        target_domain: s.target_domain,
        risk_score: s.risk_score,
        risk_level: s.risk_level,
        findings_count: Array.isArray(s.findings) ? s.findings.length : 0,
        scanned_at: s.scanned_at
      }));
  }

  const kpiTotal = document.getElementById('kpi-total-scans');
  const kpiThreats = document.getElementById('kpi-threats-blocked');
  if (kpiTotal) kpiTotal.textContent = String(totalScans);
  if (kpiThreats) kpiThreats.textContent = String(threatsBlocked);

  renderHistoryItems(items);
}

function renderHistoryItems(items) {
  const listEl = document.getElementById('history-list-container');
  if (!listEl) return;
  listEl.replaceChildren();

  if (items.length === 0) {
    const emptyP = document.createElement('p');
    emptyP.className = 'text-muted';
    emptyP.textContent = 'Aún no hay análisis registrados con los filtros seleccionados.';
    listEl.appendChild(emptyP);
    return;
  }

  for (const row of items) {
    const itemDiv = document.createElement('div');
    itemDiv.className = 'history-item';

    const leftDiv = document.createElement('div');
    const badge = document.createElement('span');
    badge.className =
      row.risk_level === 'CRITICAL'
        ? 'badge badge-critical'
        : row.risk_level === 'WARNING'
          ? 'badge badge-warning'
          : 'badge badge-safe';
    badge.textContent = `${row.risk_level} (${row.risk_score}/100)`;

    const urlLine = document.createElement('div');
    urlLine.className = 'mono';
    urlLine.style.fontWeight = '600';
    urlLine.style.marginTop = '4px';
    urlLine.style.wordBreak = 'break-all';
    urlLine.textContent = row.target_url;

    const metaLine = document.createElement('div');
    metaLine.className = 'text-muted';
    metaLine.textContent = `${row.findings_count} hallazgo(s) · ${(row.scanned_at || '').replace('T', ' ').slice(0, 19)} UTC`;

    leftDiv.append(badge, urlLine, metaLine);

    const actionsDiv = document.createElement('div');
    actionsDiv.className = 'action-btn-group';

    const viewBtn = document.createElement('button');
    viewBtn.type = 'button';
    viewBtn.className = 'btn btn-secondary btn-sm';
    viewBtn.textContent = 'Ver Detalle Forense';
    viewBtn.addEventListener('click', () => navigateTo(`/scan/${encodeURIComponent(row.scan_id)}`));

    const rescanBtn = document.createElement('button');
    rescanBtn.type = 'button';
    rescanBtn.className = 'btn btn-secondary btn-sm';
    rescanBtn.textContent = 'Re-escanear';
    rescanBtn.addEventListener('click', () =>
      executeForensicScan({ url: row.target_url, forceRefresh: true, sourceForm: 'dashboard' })
    );

    const delBtn = document.createElement('button');
    delBtn.type = 'button';
    delBtn.className = 'btn btn-secondary btn-sm';
    delBtn.style.color = '#DC2626';
    delBtn.textContent = 'Eliminar';
    delBtn.addEventListener('click', async () => {
      try {
        if (navigator.onLine && AppState.user) {
          await ApiClient.deleteScan(row.scan_id);
        }
        await OfflineDb.deleteScan(row.scan_id);
        await loadDashboardData();
      } catch (err) {
        alert(err.message || 'No fue posible eliminar el registro');
      }
    });

    actionsDiv.append(viewBtn, rescanBtn, delBtn);
    itemDiv.append(leftDiv, actionsDiv);
    listEl.appendChild(itemDiv);
  }
}

/* =========================================================================
 * PASSWORD STRENGTH METER & EVENT BINDINGS
 * ========================================================================= */
function evaluatePasswordMeter(pwd) {
  let score = 0;
  if (pwd.length >= 10) score += 25;
  if (/[A-Z]/.test(pwd) && /[a-z]/.test(pwd)) score += 25;
  if (/[0-9]/.test(pwd)) score += 25;
  if (/[^A-Za-z0-9]/.test(pwd)) score += 25;
  return score;
}

function bindEvents() {
  // Global SPA declarative navigation
  document.addEventListener('click', (e) => {
    const navTrigger = e.target.closest('[data-nav]');
    if (navTrigger) {
      e.preventDefault();
      const targetPath = navTrigger.getAttribute('data-nav');
      if (targetPath) navigateTo(targetPath);
    }
  });

  window.addEventListener('popstate', () => {
    navigateTo(window.location.pathname + window.location.search, false);
  });

  // Connectivity listeners + Offline Queue Auto-Sync
  const syncConnectivityBanner = async () => {
    AppState.isOffline = !navigator.onLine;
    const banner = document.getElementById('offline-banner');
    if (banner) banner.hidden = navigator.onLine;

    if (navigator.onLine) {
      const queued = await OfflineDb.drainPendingUrls();
      if (queued.length > 0) {
        const latest = queued[queued.length - 1];
        await executeForensicScan({ url: latest.url, sourceForm: 'home' });
      }
    }
  };

  window.addEventListener('online', syncConnectivityBanner);
  window.addEventListener('offline', syncConnectivityBanner);

  // Paste from clipboard button
  document.getElementById('home-paste-btn')?.addEventListener('click', async () => {
    try {
      const clipText = await navigator.clipboard.readText();
      const extracted = extractUrlFromSharedText(clipText) || clipText.trim();
      const input = document.getElementById('home-url-input');
      if (input && extracted) {
        input.value = extracted;
        input.focus();
      }
    } catch {
      showFeedback(
        'home-scan-error',
        'Permiso de portapapeles denegado por el navegador. Pega el enlace manualmente con Ctrl+V o pulsación larga.',
        true
      );
    }
  });

  // Home Scan Form
  document.getElementById('home-scan-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const urlVal = document.getElementById('home-url-input')?.value || '';
    await executeForensicScan({ url: urlVal, sourceForm: 'home' });
  });

  // Instant Demo Buttons
  document.getElementById('demo-phishing-btn')?.addEventListener('click', async () => {
    const demoReport = await ApiClient.buildLocalSimulationReport('critical_phishing');
    AppState.currentScan = demoReport;
    await OfflineDb.saveScan(demoReport);
    await navigateTo(`/scan/${demoReport.scan_id}`);
  });

  document.getElementById('demo-safe-btn')?.addEventListener('click', async () => {
    const demoReport = await ApiClient.buildLocalSimulationReport('safe_portal');
    AppState.currentScan = demoReport;
    await OfflineDb.saveScan(demoReport);
    await navigateTo(`/scan/${demoReport.scan_id}`);
  });

  document.getElementById('refresh-alerts-btn')?.addEventListener('click', () => {
    loadCommunityAlertsFeed();
  });

  // Advanced Scan Form
  document.getElementById('adv-scan-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = document.getElementById('adv-url-input')?.value || '';
    const userAgentProfile = document.getElementById('adv-ua-select')?.value || 'mobile_android';
    const forceRefresh = Boolean(document.getElementById('adv-force-refresh')?.checked);
    const saveSnapshot = Boolean(document.getElementById('adv-save-snapshot')?.checked);
    const caseNote = document.getElementById('adv-case-note')?.value || '';

    await executeForensicScan({
      url,
      forceRefresh,
      saveSnapshot,
      userAgentProfile,
      caseNote,
      sourceForm: 'advanced'
    });
  });

  // Dashboard Quick Scan & Tabs
  document.getElementById('dash-quick-scan-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = document.getElementById('dash-quick-url')?.value || '';
    await executeForensicScan({ url, sourceForm: 'dashboard' });
  });

  document.querySelectorAll('[data-dash-tab]').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('[data-dash-tab]').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      const tab = btn.getAttribute('data-dash-tab');
      document.getElementById('dash-panel-history').hidden = tab !== 'history';
      document.getElementById('dash-panel-profile').hidden = tab !== 'profile';
    });
  });

  document.getElementById('dash-refresh-history')?.addEventListener('click', loadDashboardData);
  document.getElementById('history-risk-filter')?.addEventListener('change', loadDashboardData);
  document.getElementById('history-search-input')?.addEventListener('input', () => {
    clearTimeout(window.__d360SearchTimer);
    window.__d360SearchTimer = setTimeout(loadDashboardData, 300);
  });

  // Password visibility toggles
  const setupPwdToggle = (btnId, inputId) => {
    document.getElementById(btnId)?.addEventListener('click', (e) => {
      const inp = document.getElementById(inputId);
      if (!inp) return;
      const isPwd = inp.type === 'password';
      inp.type = isPwd ? 'text' : 'password';
      e.currentTarget.textContent = isPwd ? 'Ocultar' : 'Ver';
    });
  };
  setupPwdToggle('login-toggle-pwd', 'login-password');
  setupPwdToggle('reg-toggle-pwd', 'reg-password');

  // Password strength bar
  document.getElementById('reg-password')?.addEventListener('input', (e) => {
    const score = evaluatePasswordMeter(e.target.value || '');
    const bar = document.getElementById('reg-strength-bar');
    const txt = document.getElementById('reg-strength-text');
    if (!bar || !txt) return;

    bar.style.width = `${score}%`;
    if (score < 50) {
      bar.style.backgroundColor = '#DC2626';
      txt.textContent = 'Fortaleza débil: agrega mayúsculas, números y símbolos (mín. 10 caracteres).';
    } else if (score < 100) {
      bar.style.backgroundColor = '#D97706';
      txt.textContent = 'Fortaleza media: completa todos los requisitos para máxima protección.';
    } else {
      bar.style.backgroundColor = '#16A34A';
      txt.textContent = 'Contraseña robusta lista para cifrado PBKDF2-HMAC-SHA512.';
    }
  });

  // Login Submit
  document.getElementById('login-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideFeedback('login-feedback');
    const email = document.getElementById('login-email')?.value || '';
    const password = document.getElementById('login-password')?.value || '';
    const remember = Boolean(document.getElementById('login-remember')?.checked);

    try {
      const res = await ApiClient.login(email, password, remember);
      AppState.user = res.data.user;
      updateAuthHeaderUi();
      await navigateTo('/dashboard');
    } catch (err) {
      showFeedback('login-feedback', err.message || 'Credenciales inválidas', true);
    }
  });

  // Register Submit
  document.getElementById('register-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideFeedback('register-feedback');
    const alias = document.getElementById('reg-alias')?.value || '';
    const email = document.getElementById('reg-email')?.value || '';
    const password = document.getElementById('reg-password')?.value || '';
    const confirm = document.getElementById('reg-password-confirm')?.value || '';
    const ethics = Boolean(document.getElementById('reg-ethics-check')?.checked);

    if (password !== confirm) {
      showFeedback('register-feedback', 'Las contraseñas ingresadas no coinciden.', true);
      return;
    }
    if (!ethics) {
      showFeedback('register-feedback', 'Debes aceptar las condiciones de uso ético ciudadano.', true);
      return;
    }

    try {
      const res = await ApiClient.register(alias, email, password);
      AppState.user = res.data.user;
      updateAuthHeaderUi();
      await navigateTo('/dashboard');
    } catch (err) {
      const detailMsg = err.details
        ? Object.values(err.details).join(' · ')
        : err.message;
      showFeedback('register-feedback', detailMsg || 'Error al registrar cuenta', true);
    }
  });

  // Logout
  document.getElementById('dash-logout-btn')?.addEventListener('click', async () => {
    try {
      await ApiClient.logout();
    } catch {
      // Ignore network failure on logout
    }
    AppState.user = null;
    updateAuthHeaderUi();
    await navigateTo('/');
  });

  // Export JSON & PDF Actions
  document.getElementById('btn-export-json')?.addEventListener('click', async () => {
    if (!AppState.currentScan) return;
    await ExportService.downloadForensicJson(AppState.currentScan);
    showFeedback(
      'detail-feedback',
      'Evidencia forense descargada en JSON con firma criptográfica SHA-256.',
      false
    );
  });

  document.getElementById('btn-export-pdf')?.addEventListener('click', async () => {
    if (!AppState.currentScan) return;
    await ExportService.printForensicPdf();
  });

  // Community Alert Modal
  const modal = document.getElementById('community-alert-modal');
  document.getElementById('btn-open-alert-modal')?.addEventListener('click', () => {
    if (!AppState.user) {
      showFeedback(
        'detail-feedback',
        'Para evitar reportes falsos o automatizados, inicia sesión con tu cuenta ciudadana antes de publicar una alerta comunitaria.',
        true
      );
      return;
    }
    if (modal) modal.hidden = false;
  });

  document.getElementById('modal-cancel-btn')?.addEventListener('click', () => {
    if (modal) modal.hidden = true;
  });

  document.getElementById('community-alert-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!AppState.currentScan) return;

    const channelReceived = document.getElementById('alert-channel-select')?.value || 'whatsapp';
    const citizenNote = document.getElementById('alert-note-input')?.value || '';

    try {
      const res = await ApiClient.publishCommunityAlert({
        scanId: AppState.currentScan.scan_id,
        channelReceived,
        citizenNote
      });
      if (modal) modal.hidden = true;
      showFeedback('detail-feedback', res.message || 'Alerta comunitaria publicada.', false);
    } catch (err) {
      if (modal) modal.hidden = true;
      showFeedback('detail-feedback', err.message || 'No fue posible publicar la alerta.', true);
    }
  });
}

/* =========================================================================
 * BOOTSTRAP PWA & SERVICE WORKER
 * ========================================================================= */
async function bootstrapApp() {
  bindEvents();

  const banner = document.getElementById('offline-banner');
  if (banner) banner.hidden = navigator.onLine;

  // Register Service Worker
  if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
      navigator.serviceWorker.register('/sw.js').catch(() => {
        // SW registration skipped on non-HTTPS/non-localhost file:// protocol
      });
    });
  }

  // Restore active citizen session silently if cookie exists
  if (navigator.onLine) {
    try {
      const meRes = await ApiClient.getMe();
      if (meRes?.data?.user) {
        AppState.user = meRes.data.user;
      }
    } catch {
      AppState.user = null;
    }
  }

  updateAuthHeaderUi();
  await navigateTo(window.location.pathname + window.location.search, false);
}

bootstrapApp();
