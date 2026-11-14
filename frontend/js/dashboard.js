import {
  ApiClient,
  formatRelativeTime,
  initMobileNavbar,
  setPendingScanId,
  showToast,
  syncNavbarAuth,
} from './api-client.js';
import { ExportService } from './export-service.js';
import { initPwaSupport } from './pwa-install.js';

let activeFilter = '';

document.addEventListener('DOMContentLoaded', async () => {
  initMobileNavbar();
  initPwaSupport();

  const isDashboardPage = Boolean(document.getElementById('dashboard-history-tbody'));
  const isAdvancedScanPage = Boolean(document.getElementById('advanced-scan-form'));

  if (isDashboardPage) {
    await bootDashboard();
  }

  if (isAdvancedScanPage) {
    await syncNavbarAuth();
    bootAdvancedScanForm();
  }
});

async function bootDashboard() {
  let user = null;
  try {
    const me = await ApiClient.getMe();
    user = me?.data?.user;
  } catch {
    window.location.href = '/login';
    return;
  }

  if (!user) {
    window.location.href = '/login';
    return;
  }

  // Welcome banner if newly registered
  const qs = new URLSearchParams(window.location.search);
  if (qs.get('welcome') === '1') {
    showToast(`¡Bienvenido, ${user.alias}! Tu Escudo Personal está activo.`);
  }

  const greetingEl = document.getElementById('dash-user-greeting');
  if (greetingEl) greetingEl.textContent = `Hola, ${user.alias}`;

  const planEl = document.getElementById('stat-active-plan');
  if (planEl) {
    planEl.textContent =
      user.plan_tier === 'family_shield'
        ? 'Escudo Familiar'
        : user.plan_tier === 'verified_merchant'
        ? 'Comercio Verificado'
        : 'Ciudadano Gratis';
  }

  const logoutBtns = document.querySelectorAll('[data-logout-btn]');
  logoutBtns.forEach((btn) => {
    btn.addEventListener('click', async () => {
      await ApiClient.logout();
      window.location.href = '/';
    });
  });

  // Quick scan bar in dashboard
  const quickForm = document.getElementById('dash-quick-scan-form');
  const quickInput = document.getElementById('dash-quick-url');
  const quickBtn = document.getElementById('dash-quick-submit');
  if (quickForm && quickInput) {
    quickForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const urlVal = quickInput.value.trim();
      if (!urlVal) return;

      if (quickBtn) quickBtn.disabled = true;
      try {
        const res = await ApiClient.runScan({
          url: urlVal,
          force_refresh: false,
          save_snapshot: true,
        });
        window.location.href = `/scan/${encodeURIComponent(res.data.scan_id)}`;
      } catch (err) {
        showToast(err.message || 'Enlace inválido o inaccesible.', true);
        if (quickBtn) quickBtn.disabled = false;
      }
    });
  }

  // Risk filter pills
  document.querySelectorAll('[data-risk-filter]').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('[data-risk-filter]').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      activeFilter = btn.getAttribute('data-risk-filter') || '';
      loadHistoryTable();
    });
  });

  await loadHistoryTable();
}

async function loadHistoryTable() {
  const tbody = document.getElementById('dashboard-history-tbody');
  const totalStatEl = document.getElementById('stat-total-scans');
  const avoidedStatEl = document.getElementById('stat-threats-avoided');

  if (!tbody) return;

  try {
    const res = await ApiClient.getUserHistory(1, 25, activeFilter);
    const items = res?.data?.items || [];
    const stats = res?.data?.stats;

    if (stats) {
      if (totalStatEl) totalStatEl.textContent = String(stats.total_analyzed ?? 0);
      if (avoidedStatEl) avoidedStatEl.textContent = String(stats.threats_avoided ?? 0);
    }

    tbody.textContent = '';

    if (items.length === 0) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 5;
      td.style.textAlign = 'center';
      td.style.padding = '32px 16px';
      td.style.color = '#94A3B8';
      td.textContent = activeFilter
        ? 'No tienes análisis registrados con ese filtro de riesgo.'
        : 'Aún no tienes enlaces guardados. Analiza tu primer enlace sospechoso en la barra superior.';
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    items.forEach((item) => {
      const tr = document.createElement('tr');

      // 1. Semáforo con LED vectorial
      const tdBadge = document.createElement('td');
      const badge = document.createElement('span');
      badge.className =
        item.risk_level === 'CRITICAL'
          ? 'badge badge-critical tabular-nums'
          : item.risk_level === 'WARNING'
          ? 'badge badge-warning tabular-nums'
          : 'badge badge-safe tabular-nums';

      const led = document.createElement('span');
      led.className =
        item.risk_level === 'CRITICAL'
          ? 'status-led critical'
          : item.risk_level === 'WARNING'
          ? 'status-led warning'
          : 'status-led safe';

      const bText = document.createElement('span');
      bText.textContent =
        item.risk_level === 'CRITICAL'
          ? `Peligro (${item.risk_score})`
          : item.risk_level === 'WARNING'
          ? `Precaución (${item.risk_score})`
          : `Seguro (${item.risk_score})`;

      badge.append(led, bText);
      tdBadge.appendChild(badge);

      // 2. Dominio / URL
      const tdDomain = document.createElement('td');
      const domStrong = document.createElement('div');
      domStrong.className = 'mono';
      domStrong.style.fontWeight = '600';
      domStrong.textContent = item.target_domain;
      const verdictSub = document.createElement('div');
      verdictSub.style.fontSize = '0.8rem';
      verdictSub.style.color = '#94A3B8';
      verdictSub.textContent = item.citizen_verdict_title || '';
      tdDomain.append(domStrong, verdictSub);

      // 3. Fecha
      const tdDate = document.createElement('td');
      tdDate.style.color = '#94A3B8';
      tdDate.textContent = formatRelativeTime(item.scanned_at);

      // 4. Acciones
      const tdActions = document.createElement('td');
      const actionsWrap = document.createElement('div');
      actionsWrap.style.display = 'flex';
      actionsWrap.style.gap = '8px';
      actionsWrap.style.flexWrap = 'wrap';

      const viewLink = document.createElement('a');
      viewLink.href = `/scan/${encodeURIComponent(item.scan_id)}`;
      viewLink.className = 'btn btn-outline-cyan btn-sm';
      viewLink.textContent = 'Ver Reporte';

      const dlBtn = document.createElement('button');
      dlBtn.type = 'button';
      dlBtn.className = 'btn btn-ghost btn-sm';
      dlBtn.textContent = 'Descargar Evidencia';
      dlBtn.addEventListener('click', async () => {
        try {
          const full = await ApiClient.getScanById(item.scan_id);
          ExportService.downloadJsonEvidence(full.data);
        } catch {
          showToast('No se pudo descargar la evidencia.', true);
        }
      });

      actionsWrap.append(viewLink, dlBtn);
      tdActions.appendChild(actionsWrap);

      tr.append(tdBadge, tdDomain, tdDate, tdActions);
      tbody.appendChild(tr);
    });
  } catch (err) {
    showToast(err.message || 'Error al cargar tu historial.', true);
  }
}

function bootAdvancedScanForm() {
  const form = document.getElementById('advanced-scan-form');
  if (!form) return;

  const submitBtn = document.getElementById('adv-scan-submit');
  const errBox = document.getElementById('adv-scan-error');

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (errBox) errBox.style.display = 'none';

    const urlVal = document.getElementById('adv-url-input')?.value?.trim() || '';
    const forceRefresh = Boolean(document.getElementById('adv-force-refresh')?.checked);
    const selectedDevice =
      document.querySelector('input[name="device_profile"]:checked')?.value || 'android';

    if (!urlVal) return;

    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.textContent = 'Ejecutando Rayos X Forenses...';
    }

    try {
      const res = await ApiClient.runScan({
        url: urlVal,
        force_refresh: forceRefresh,
        save_snapshot: true,
        device_profile: selectedDevice,
      });

      setPendingScanId(res.data.scan_id);
      window.location.href = `/scan/${encodeURIComponent(res.data.scan_id)}`;
    } catch (err) {
      if (errBox) {
        errBox.textContent = err.message || 'No se pudo analizar la dirección ingresada.';
        errBox.style.display = 'block';
      }
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Ejecutar Rayos X';
      }
    }
  });
}
