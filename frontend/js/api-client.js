/**
 * Detector360 — API Client & Shared UI Helpers
 */

const API_BASE = window.D360_API_BASE || '/api/v1';

export class ApiClient {
  static async request(path, options = {}) {
    const url = `${API_BASE}${path}`;
    const headers = {
      Accept: 'application/json',
      ...(options.body ? { 'Content-Type': 'application/json' } : {}),
      ...(options.headers || {}),
    };

    try {
      const response = await fetch(url, {
        ...options,
        headers,
        credentials: 'include',
      });

      let payload = null;
      try {
        payload = await response.json();
      } catch {
        payload = null;
      }

      if (!response.ok || (payload && payload.success === false)) {
        const message =
          payload?.error?.message ||
          'No pudimos completar la solicitud en este momento. Intenta de nuevo.';
        const code = payload?.error?.code || `HTTP_${response.status}`;
        const err = new Error(message);
        err.code = code;
        err.status = response.status;
        throw err;
      }

      return payload;
    } catch (err) {
      if (err.code) throw err;
      const netErr = new Error(
        'Verifica tu conexión a internet e inténtalo nuevamente en unos segundos.'
      );
      netErr.code = 'NETWORK_ERROR';
      throw netErr;
    }
  }

  static getLandingFeed() {
    return this.request('/commercial/landing-feed', { method: 'GET' });
  }

  static createLead(data) {
    return this.request('/commercial/leads', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  static runScan(data) {
    return this.request('/scans', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  static getScanById(scanId) {
    return this.request(`/scans/${encodeURIComponent(scanId)}`, { method: 'GET' });
  }

  static sendClarityFeedback(scanId, isClear) {
    return this.request(`/scans/${encodeURIComponent(scanId)}/feedback`, {
      method: 'POST',
      body: JSON.stringify({ is_clear: isClear }),
    });
  }

  static getUserHistory(page = 1, limit = 15, riskLevel = '') {
    const qs = new URLSearchParams({ page: String(page), limit: String(limit) });
    if (riskLevel) qs.set('risk_level', riskLevel);
    return this.request(`/scans/history?${qs.toString()}`, { method: 'GET' });
  }

  static publishCommunityAlert(data) {
    return this.request('/community/alerts', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  static register(data) {
    return this.request('/auth/register', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  static login(data) {
    return this.request('/auth/login', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  static logout() {
    return this.request('/auth/logout', { method: 'POST' });
  }

  static getMe() {
    return this.request('/auth/me', { method: 'GET' });
  }

  // --- C.I.C.P.C Cybercrime Division Command & Citizen Reporting ---
  static submitCicpcCase(data) {
    return this.request('/cicpc/cases/report', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  static cicpcLogin(data) {
    return this.request('/cicpc/auth/login', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  static cicpcLogout() {
    return this.request('/cicpc/auth/logout', { method: 'POST' });
  }

  static cicpcMe() {
    return this.request('/cicpc/auth/me', { method: 'GET' });
  }

  static cicpcDashboard() {
    return this.request('/cicpc/dashboard', { method: 'GET' });
  }

  static cicpcListCases(filters = {}) {
    const qs = new URLSearchParams();
    if (filters.status) qs.set('status', filters.status);
    if (filters.priority) qs.set('priority', filters.priority);
    if (filters.channel) qs.set('channel', filters.channel);
    if (filters.search) qs.set('search', filters.search);
    return this.request(`/cicpc/cases?${qs.toString()}`, { method: 'GET' });
  }

  static cicpcGetCaseDetail(caseId) {
    return this.request(`/cicpc/cases/${encodeURIComponent(caseId)}`, { method: 'GET' });
  }

  static cicpcUpdateCase(caseId, data) {
    return this.request(`/cicpc/cases/${encodeURIComponent(caseId)}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    });
  }

  static cicpcExportSuricataRules() {
    return this.request('/cicpc/rules/suricata', { method: 'GET' });
  }

  // --------------------------------------------------------------------------
  // Módulo 5: Protección Integral Adulto Mayor y Ángel Guardián
  // --------------------------------------------------------------------------
  static analyzeSeniorMessage(messageText) {
    return this.request('/senior/analyze-message', {
      method: 'POST',
      body: JSON.stringify({ message_text: messageText }),
    });
  }

  static searchVerifiedDirectory(query = '', category = 'ALL') {
    const qs = new URLSearchParams();
    if (query) qs.set('q', query);
    if (category && category !== 'ALL') qs.set('category', category);
    return this.request(`/senior/directory?${qs.toString()}`, { method: 'GET' });
  }

  static getSeniorSimulator() {
    return this.request('/senior/simulator', { method: 'GET' });
  }

  static createGuardianAlert(payload) {
    return this.request('/senior/guardian/ask', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  static getGuardianConsultation(token) {
    return this.request(`/senior/guardian/${encodeURIComponent(token)}`, {
      method: 'GET',
    });
  }

  static replyGuardianConsultation(token, decision, note = '') {
    return this.request(`/senior/guardian/${encodeURIComponent(token)}/reply`, {
      method: 'POST',
      body: JSON.stringify({ decision, note }),
    });
  }

  static submitSeniorEmergency(payload) {
    return this.request('/senior/emergency-report', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  // --------------------------------------------------------------------------
  // Portal Dedicado del Familiar (/familiar): Novedades de la Persona Mayor
  // --------------------------------------------------------------------------
  static registerFamilyLink(payload) {
    return this.request('/senior/family/register', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  static loginFamilyPortal(familyCode, accessKey) {
    return this.request('/senior/family/login', {
      method: 'POST',
      body: JSON.stringify({ family_code: familyCode, access_key: accessKey }),
    });
  }

  static logoutFamilyPortal() {
    return this.request('/senior/family/logout', { method: 'POST' });
  }

  static getFamilyDashboard(filter = 'ALL') {
    const qs = new URLSearchParams();
    if (filter && filter !== 'ALL') qs.set('filter', filter);
    return this.request(`/senior/family/dashboard?${qs.toString()}`, { method: 'GET' });
  }

  static reportSeniorDeviceEvent(payload) {
    return this.request('/senior/family/events', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  static updateFamilyEventDecision(eventId, status, note = '') {
    return this.request(`/senior/family/events/${encodeURIComponent(eventId)}`, {
      method: 'PATCH',
      body: JSON.stringify({ status, note }),
    });
  }

  static sendFamilyBroadcast(message) {
    return this.request('/senior/family/broadcast', {
      method: 'POST',
      body: JSON.stringify({ message }),
    });
  }

  static getSeniorLiveSync(familyCode) {
    return this.request(`/senior/family/senior-sync/${encodeURIComponent(familyCode)}`, {
      method: 'GET',
    });
  }
}

export function showToast(message, isError = false) {
  let container = document.getElementById('d360-toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'd360-toast-container';
    container.className = 'toast-container';
    container.setAttribute('aria-live', 'polite');
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  toast.className = isError ? 'toast error' : 'toast';
  toast.textContent = message;
  container.appendChild(toast);

  setTimeout(() => {
    toast.remove();
  }, 4200);
}

export function setPendingScanId(scanId) {
  if (!scanId) return;
  try {
    sessionStorage.setItem('d360_pending_scan_id', scanId);
  } catch {
    // ignore storage restriction
  }
}

export function getPendingScanId() {
  try {
    return sessionStorage.getItem('d360_pending_scan_id') || '';
  } catch {
    return '';
  }
}

export function clearPendingScanId() {
  try {
    sessionStorage.removeItem('d360_pending_scan_id');
  } catch {
    // ignore
  }
}

export function initMobileNavbar() {
  const toggleBtn = document.getElementById('mobile-menu-btn');
  const navLinks = document.getElementById('navbar-links');
  if (toggleBtn && navLinks) {
    toggleBtn.addEventListener('click', () => {
      const expanded = navLinks.classList.toggle('open');
      toggleBtn.setAttribute('aria-expanded', String(expanded));
    });
  }
}

export async function syncNavbarAuth() {
  const actionsWrap = document.getElementById('navbar-auth-actions');
  if (!actionsWrap) return null;

  try {
    const res = await ApiClient.getMe();
    const user = res?.data?.user;
    if (user) {
      actionsWrap.textContent = '';

      const dashLink = document.createElement('a');
      dashLink.href = '/dashboard';
      dashLink.className = 'btn btn-outline-cyan btn-sm';
      dashLink.textContent = `Escudo de ${user.alias}`;

      const logoutBtn = document.createElement('button');
      logoutBtn.type = 'button';
      logoutBtn.className = 'btn btn-ghost btn-sm';
      logoutBtn.textContent = 'Salir';
      logoutBtn.addEventListener('click', async () => {
        await ApiClient.logout();
        window.location.href = '/';
      });

      actionsWrap.append(dashLink, logoutBtn);
      return user;
    }
  } catch {
    // Anonymous visitor — keep default Login / Register buttons
  }
  return null;
}

export function formatRelativeTime(isoDate) {
  if (!isoDate) return 'Hace instantes';
  const diffSec = Math.max(5, Math.floor((Date.now() - new Date(isoDate).getTime()) / 1000));
  if (diffSec < 60) return `Hace ${diffSec} seg`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `Hace ${diffMin} min`;
  const diffHrs = Math.floor(diffMin / 60);
  if (diffHrs < 24) return `Hace ${diffHrs} h`;
  return new Date(isoDate).toLocaleDateString('es-ES', { day: '2-digit', month: 'short' });
}
