import { ApiClient, formatRelativeTime, initMobileNavbar, showToast } from './api-client.js';

const EVENT_TYPE_LABELS = {
  ASK_GUARDIAN: 'Duda en 1 Toque del Adulto Mayor',
  AUTO_CRITICAL_ALERT: 'Alerta Crítica Automática (Escudo Familiar)',
  EMERGENCY_TRIGGERED: 'EMERGENCIA: Reportó entrega de clave o pago',
  MESSAGE_SCAN: 'Mensaje WhatsApp / SMS Revisado',
  QR_SCAN: 'Código QR Revisado con Cámara Segura',
  URL_SCAN: 'Enlace Web Inspeccionado',
};

const FAMILY_STATUS_LABELS = {
  PENDING: 'Esperando tu orientación',
  DANGER_DELETE: 'Indicaste: BÓRRALO YA (Peligro)',
  SAFE_APPROVED: 'Indicaste: ES SEGURO',
  RESOLVED_BY_CALL: 'Atendido por llamada telefónica',
  INFO: 'Registro informativo',
};

let activeFilter = 'ALL';
let currentProfile = null;
let autoRefreshTimer = null;

document.addEventListener('DOMContentLoaded', async () => {
  initMobileNavbar();
  bindAuthForms();
  bindDashboardControls();
  await tryLoadActiveSession();
});

async function tryLoadActiveSession() {
  try {
    const res = await ApiClient.getFamilyDashboard(activeFilter);
    showDashboardView(res.data);
    startAutoRefresh();
  } catch {
    showAuthGateView();
  }
}

function showAuthGateView() {
  const gate = document.getElementById('family-auth-gate');
  const shell = document.getElementById('family-dashboard-shell');
  const logoutBtn = document.getElementById('btn-family-logout');
  if (gate) gate.style.display = 'block';
  if (shell) shell.style.display = 'none';
  if (logoutBtn) logoutBtn.style.display = 'none';
  if (autoRefreshTimer) {
    clearInterval(autoRefreshTimer);
    autoRefreshTimer = null;
  }
}

function showDashboardView(data) {
  const gate = document.getElementById('family-auth-gate');
  const shell = document.getElementById('family-dashboard-shell');
  const logoutBtn = document.getElementById('btn-family-logout');
  if (gate) gate.style.display = 'none';
  if (shell) shell.style.display = 'block';
  if (logoutBtn) logoutBtn.style.display = 'inline-flex';

  renderFamilyDashboard(data);
}

function bindAuthForms() {
  const loginForm = document.getElementById('family-login-form');
  const demoBtn = document.getElementById('btn-demo-family-login');
  const regForm = document.getElementById('family-register-form');

  if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const code = document.getElementById('login-family-code')?.value.trim() || '';
      const key = document.getElementById('login-access-key')?.value.trim() || '';
      await executeFamilyLogin(code, key);
    });
  }

  if (demoBtn) {
    demoBtn.addEventListener('click', async () => {
      const codeEl = document.getElementById('login-family-code');
      const keyEl = document.getElementById('login-access-key');
      if (codeEl) codeEl.value = 'FAM-ABUELO-2026';
      if (keyEl) keyEl.value = 'ClaveFamiliar2026!';
      await executeFamilyLogin('FAM-ABUELO-2026', 'ClaveFamiliar2026!');
    });
  }

  if (regForm) {
    regForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('btn-family-reg-submit');
      if (btn) btn.disabled = true;

      try {
        const payload = {
          senior_name: document.getElementById('reg-senior-name')?.value.trim() || '',
          senior_phone: document.getElementById('reg-senior-phone')?.value.trim() || '',
          guardian_name: document.getElementById('reg-guardian-name')?.value.trim() || '',
          guardian_phone: document.getElementById('reg-guardian-phone')?.value.trim() || '',
          access_key: document.getElementById('reg-access-key')?.value.trim() || '',
        };

        const res = await ApiClient.registerFamilyLink(payload);
        showToast(`Vínculo creado: Código ${res.data.family_code}`);
        await refreshDashboard();
        startAutoRefresh();
      } catch (err) {
        showToast(err.message || 'No se pudo crear el vínculo familiar.', true);
      } finally {
        if (btn) btn.disabled = false;
      }
    });
  }
}

async function executeFamilyLogin(code, key) {
  const btn = document.getElementById('btn-family-login-submit');
  if (btn) btn.disabled = true;
  try {
    await ApiClient.loginFamilyPortal(code, key);
    showToast('Bienvenido/a a la Sala de Cuidado Familiar.');
    await refreshDashboard();
    startAutoRefresh();
  } catch (err) {
    showToast(err.message || 'Credenciales familiares incorrectas.', true);
  } finally {
    if (btn) btn.disabled = false;
  }
}

function bindDashboardControls() {
  const logoutBtn = document.getElementById('btn-family-logout');
  const refreshBtn = document.getElementById('btn-refresh-family-feed');
  const copyPairBtn = document.getElementById('btn-copy-pairing-link');
  const broadcastForm = document.getElementById('family-broadcast-form');
  const broadcastInput = document.getElementById('family-broadcast-input');

  if (logoutBtn) {
    logoutBtn.addEventListener('click', async () => {
      await ApiClient.logoutFamilyPortal();
      showAuthGateView();
      showToast('Sesión familiar cerrada.');
    });
  }

  if (refreshBtn) {
    refreshBtn.addEventListener('click', async () => {
      await refreshDashboard();
      showToast('Novedades sincronizadas en tiempo real.');
    });
  }

  if (copyPairBtn) {
    copyPairBtn.addEventListener('click', async () => {
      if (!currentProfile?.pairing_url) return;
      try {
        await navigator.clipboard.writeText(currentProfile.pairing_url);
        showToast('Enlace de vinculación copiado. Ábrelo una vez en el teléfono de tu familiar mayor.');
      } catch {
        showToast(`Enlace: ${currentProfile.pairing_url}`);
      }
    });
  }

  document.querySelectorAll('[data-preset-broadcast]').forEach((chip) => {
    chip.addEventListener('click', () => {
      const txt = chip.getAttribute('data-preset-broadcast') || '';
      if (broadcastInput && txt) {
        broadcastInput.value = txt;
        broadcastInput.focus();
      }
    });
  });

  if (broadcastForm && broadcastInput) {
    broadcastForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const msg = broadcastInput.value.trim();
      if (!msg) return;
      try {
        const res = await ApiClient.sendFamilyBroadcast(msg);
        showToast(res.message || 'Aviso enviado a la pantalla de tu familiar.');
        await refreshDashboard();
      } catch (err) {
        showToast(err.message || 'No se pudo enviar el aviso.', true);
      }
    });
  }

  document.querySelectorAll('[data-family-filter]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      activeFilter = btn.getAttribute('data-family-filter') || 'ALL';
      document.querySelectorAll('[data-family-filter]').forEach((b) => {
        b.classList.toggle('btn-primary', b === btn);
        b.classList.toggle('btn-ghost', b !== btn);
      });
      await refreshDashboard();
    });
  });
}

async function refreshDashboard() {
  const res = await ApiClient.getFamilyDashboard(activeFilter);
  showDashboardView(res.data);
}

function startAutoRefresh() {
  if (autoRefreshTimer) clearInterval(autoRefreshTimer);
  autoRefreshTimer = setInterval(() => {
    refreshDashboard().catch(() => {});
  }, 10000);
}

function renderFamilyDashboard(data) {
  const p = data.family_profile;
  const kpis = data.kpis;
  currentProfile = p;

  const badge = document.getElementById('dash-overall-badge');
  if (badge) {
    if (kpis.overall_status === 'EMERGENCY') {
      badge.className = 'badge badge-critical';
      badge.textContent = 'EMERGENCIA ACTIVA: LLAMAR DE INMEDIATO';
    } else if (kpis.overall_status === 'NEEDS_ATTENTION') {
      badge.className = 'badge badge-warning';
      badge.textContent = 'NOVEDADES PENDIENTES DE TU REVISIÓN';
    } else {
      badge.className = 'badge badge-safe';
      badge.textContent = 'TRANQUILO Y PROTEGIDO';
    }
  }

  setText('dash-family-code', `Código Familiar: ${p.family_code}`);
  setText('dash-senior-heading', `Cuidando a: ${p.senior_name}`);
  setText(
    'dash-last-activity',
    `Última actividad registrada en su teléfono: ${formatRelativeTime(p.last_senior_activity_at)}`
  );

  const callBtn = document.getElementById('dash-call-senior-btn');
  if (callBtn) {
    const cleanPhone = (p.senior_phone || '').replace(/[^\d+]/g, '');
    if (cleanPhone) {
      callBtn.href = `tel:${cleanPhone}`;
      callBtn.style.display = 'inline-flex';
      callBtn.textContent = `Llamar a ${p.senior_name} (${p.senior_phone})`;
    } else {
      callBtn.style.display = 'none';
    }
  }

  const waPairBtn = document.getElementById('dash-wa-pair-btn');
  if (waPairBtn && p.pairing_url) {
    const cleanSeniorDigits = (p.senior_phone || '').replace(/[^\d]/g, '');
    const waText = `Hola ${p.senior_name}, soy ${p.guardian_name}. Toca este enlace seguro una sola vez para dejar tu teléfono protegido conmigo en Detector360: ${p.pairing_url}`;
    waPairBtn.href = cleanSeniorDigits
      ? `https://wa.me/${cleanSeniorDigits}?text=${encodeURIComponent(waText)}`
      : `https://wa.me/?text=${encodeURIComponent(waText)}`;
  }

  setText('fkpi-pending', String(kpis.pending_consultations));
  setText('fkpi-critical', String(kpis.critical_threats_blocked));
  setText('fkpi-total', String(kpis.total_events));
  setText('fkpi-guardian-name', p.guardian_name);

  const bInput = document.getElementById('family-broadcast-input');
  if (bInput && !bInput.value && p.latest_family_broadcast) {
    bInput.placeholder = `Último aviso enviado: "${p.latest_family_broadcast}"`;
  }

  renderEventsList(data.events || [], p.senior_name);
}

function renderEventsList(events, seniorName) {
  const container = document.getElementById('family-events-list');
  if (!container) return;
  container.textContent = '';

  if (events.length === 0) {
    const empty = document.createElement('p');
    empty.style.color = '#C8DDF8';
    empty.textContent = 'No hay novedades en esta categoría por ahora. Todo está en calma.';
    container.appendChild(empty);
    return;
  }

  events.forEach((ev) => {
    const card = document.createElement('article');
    card.style.background =
      ev.family_status === 'PENDING'
        ? 'rgba(127, 29, 29, 0.36)'
        : 'rgba(2, 11, 34, 0.85)';
    card.style.border =
      ev.risk_level === 'CRITICAL'
        ? '1.5px solid rgba(255, 46, 76, 0.65)'
        : ev.risk_level === 'WARNING'
        ? '1.5px solid rgba(250, 204, 21, 0.55)'
        : '1.5px solid rgba(16, 185, 129, 0.45)';
    card.style.borderRadius = '16px';
    card.style.padding = '18px';
    card.style.display = 'grid';
    card.style.gap = '10px';

    const topRow = document.createElement('div');
    topRow.style.display = 'flex';
    topRow.style.flexWrap = 'wrap';
    topRow.style.justifyContent = 'space-between';
    topRow.style.alignItems = 'center';
    topRow.style.gap = '8px';

    const leftMeta = document.createElement('div');
    leftMeta.style.display = 'flex';
    leftMeta.style.flexWrap = 'wrap';
    leftMeta.style.alignItems = 'center';
    leftMeta.style.gap = '8px';

    const riskBadge = document.createElement('span');
    riskBadge.className =
      ev.risk_level === 'CRITICAL'
        ? 'badge badge-critical'
        : ev.risk_level === 'WARNING'
        ? 'badge badge-warning'
        : 'badge badge-safe';
    riskBadge.textContent = `Riesgo ${ev.risk_score}/100`;

    const typeLabel = document.createElement('strong');
    typeLabel.style.color = '#00E1FF';
    typeLabel.style.fontSize = '0.94rem';
    typeLabel.textContent = EVENT_TYPE_LABELS[ev.event_type] || ev.event_type;

    leftMeta.append(riskBadge, typeLabel);

    const timeSpan = document.createElement('span');
    timeSpan.style.fontSize = '0.84rem';
    timeSpan.style.color = '#9CC4F6';
    timeSpan.textContent = formatRelativeTime(ev.created_at);

    topRow.append(leftMeta, timeSpan);

    const summary = document.createElement('p');
    summary.style.margin = '0';
    summary.style.color = '#FFFFFF';
    summary.style.fontSize = '1rem';
    summary.textContent = ev.content_summary;

    card.append(topRow, summary);

    if (ev.target_url) {
      const urlBox = document.createElement('div');
      urlBox.className = 'mono';
      urlBox.style.fontSize = '0.84rem';
      urlBox.style.color = '#FDE047';
      urlBox.style.wordBreak = 'break-all';
      urlBox.textContent = `Dirección detectada (ofuscada): ${ev.target_url.replace(/\./g, '[.]')}`;
      card.appendChild(urlBox);
    }

    const statusLine = document.createElement('div');
    statusLine.style.fontSize = '0.88rem';
    statusLine.style.color =
      ev.family_status === 'PENDING' ? '#FDE047' : '#6EE7B7';
    statusLine.textContent = `Estado familiar: ${FAMILY_STATUS_LABELS[ev.family_status] || ev.family_status}${
      ev.family_note ? ` — Nota: "${ev.family_note}"` : ''
    }`;
    card.appendChild(statusLine);

    const actionsWrap = document.createElement('div');
    actionsWrap.style.display = 'flex';
    actionsWrap.style.flexWrap = 'wrap';
    actionsWrap.style.alignItems = 'center';
    actionsWrap.style.gap = '8px';
    actionsWrap.style.marginTop = '4px';

    const noteInput = document.createElement('input');
    noteInput.type = 'text';
    noteInput.className = 'form-input';
    noteInput.style.flex = '1 1 210px';
    noteInput.style.minHeight = '38px';
    noteInput.style.padding = '6px 12px';
    noteInput.style.fontSize = '0.86rem';
    noteInput.value = ev.family_note || '';
    noteInput.placeholder = `Nota opcional para ${seniorName}...`;

    const btnDanger = document.createElement('button');
    btnDanger.type = 'button';
    btnDanger.className = 'btn btn-primary btn-sm';
    btnDanger.style.background = '#DC2626';
    btnDanger.style.borderColor = '#FCA5A5';
    btnDanger.textContent = 'Indicar: BÓRRALO YA';
    btnDanger.addEventListener('click', () =>
      submitEventDecision(
        ev.id,
        'DANGER_DELETE',
        noteInput.value.trim() || 'Bórralo enseguida, es un intento de estafa.'
      )
    );

    const btnSafe = document.createElement('button');
    btnSafe.type = 'button';
    btnSafe.className = 'btn btn-outline-cyan btn-sm';
    btnSafe.style.borderColor = '#10B981';
    btnSafe.style.color = '#A7F3D0';
    btnSafe.textContent = 'Indicar: ES SEGURO';
    btnSafe.addEventListener('click', () =>
      submitEventDecision(
        ev.id,
        'SAFE_APPROVED',
        noteInput.value.trim() || 'Ya lo verifiqué, puedes abrirlo con calma.'
      )
    );

    const btnCalled = document.createElement('button');
    btnCalled.type = 'button';
    btnCalled.className = 'btn btn-ghost btn-sm';
    btnCalled.textContent = 'Marcar: Ya lo llamé';
    btnCalled.addEventListener('click', () =>
      submitEventDecision(
        ev.id,
        'RESOLVED_BY_CALL',
        noteInput.value.trim() || 'Atendido mediante llamada directa.'
      )
    );

    actionsWrap.append(noteInput, btnDanger, btnSafe, btnCalled);

    if (ev.scan_id) {
      const xrayLink = document.createElement('a');
      xrayLink.href = `/scan/${encodeURIComponent(ev.scan_id)}`;
      xrayLink.target = '_blank';
      xrayLink.rel = 'noopener noreferrer';
      xrayLink.className = 'btn btn-ghost btn-sm';
      xrayLink.textContent = 'Ver Rayos X Forense';
      actionsWrap.appendChild(xrayLink);
    }

    card.appendChild(actionsWrap);
    container.appendChild(card);
  });
}

async function submitEventDecision(eventId, status, note) {
  try {
    const res = await ApiClient.updateFamilyEventDecision(eventId, status, note);
    showToast(res.message || 'Respuesta registrada.');
    await refreshDashboard();
  } catch (err) {
    showToast(err.message || 'No se pudo actualizar la novedad.', true);
  }
}

function setText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}
