import { ApiClient, formatRelativeTime, showToast } from './api-client.js';

const ACTION_LABELS = {
  NONE: 'Pendiente de asignación',
  ISP_DNS_BLOCK_REQUEST: 'Bloqueo DNS ISP / CONATEL',
  REGISTRAR_TAKEDOWN: 'Takedown Internacional Hosting',
  BANKING_FRAUD_ALERT: 'Alerta Interbancaria SUDEBAN',
  TRACE_EXFILTRATION_SERVER: 'Rastreo Servidor Receptor / IP',
  PUBLIC_PREVENTION_BULLETIN: 'Boletín Prevención Ciudadana',
  FIELD_INVESTIGATION_OPENED: 'Investigación Penal / Telefónica',
};

const STATUS_LABELS = {
  pending: 'Pendiente',
  in_analysis: 'En Análisis Experto',
  strategic_action: 'Acción Estratégica',
  mitigated: 'Neutralizado',
  archived: 'Archivado',
};

const IMPACT_LABELS = {
  PREVENTIVE: 'Preventivo (Sin entrega de datos)',
  CREDENTIALS_EXPOSED: 'Exposición de Claves / Cédula',
  FINANCIAL_LOSS: 'Afectación / Pérdida Económica',
};

const SOURCE_LABELS = {
  CITIZEN_COMPLAINT: 'Denuncia Directa Ciudadana',
  COMMUNITY_ALERT: 'Alerta Comunitaria Verificada',
  AUTO_CRITICAL_DETECTION: 'Detección Crítica Automática',
};

const CHANNEL_LABELS = {
  whatsapp: 'WhatsApp',
  sms: 'Mensaje SMS',
  social: 'Redes Sociales',
  email: 'Correo Electrónico',
  telegram: 'Telegram',
  web: 'Sitio Web / Anuncio',
};

let currentOfficer = null;
let currentCases = [];
let selectedCaseId = '';
let selectedCasePayload = null;

document.addEventListener('DOMContentLoaded', async () => {
  await verifyAndBootCommandCenter();
});

async function verifyAndBootCommandCenter() {
  const gateEl = document.getElementById('cicpc-auth-gate');
  const shellEl = document.getElementById('cicpc-app-shell');

  try {
    const overviewRes = await ApiClient.cicpcDashboard();
    const data = overviewRes.data;
    currentOfficer = data.officer;

    if (gateEl) gateEl.style.display = 'none';
    if (shellEl) shellEl.style.display = 'block';

    populateOfficerHeader(currentOfficer);
    renderDashboardStats(data);
    bindToolbarAndFilters();
    bindDecisionForm();

    await reloadCasesList(true);
  } catch {
    window.location.replace('/cicpc/login');
  }
}

function populateOfficerHeader(officer) {
  const nameEl = document.getElementById('officer-name-label');
  const badgeEl = document.getElementById('officer-badge-label');
  if (nameEl) nameEl.textContent = officer.full_name;
  if (badgeEl) badgeEl.textContent = `${officer.badge_id} • ${officer.rank_title}`;
}

function bindToolbarAndFilters() {
  const refreshBtn = document.getElementById('btn-refresh-command');
  const suricataBtn = document.getElementById('btn-export-suricata');
  const csvBtn = document.getElementById('btn-export-csv');
  const logoutBtn = document.getElementById('btn-cicpc-logout');
  const searchInput = document.getElementById('filter-search-input');
  const statusSelect = document.getElementById('filter-status-select');
  const prioSelect = document.getElementById('filter-priority-select');
  const dlDossierBtn = document.getElementById('btn-download-dossier');
  const printBtn = document.getElementById('btn-print-dossier');

  if (refreshBtn) {
    refreshBtn.addEventListener('click', async () => {
      await refreshAllTelemetry();
      showToast('Sala situacional sincronizada en tiempo real.');
    });
  }

  if (logoutBtn) {
    logoutBtn.addEventListener('click', async () => {
      await ApiClient.cicpcLogout();
      window.location.replace('/cicpc/login');
    });
  }

  if (suricataBtn) {
    suricataBtn.addEventListener('click', () => exportSuricataIdsRules(suricataBtn));
  }

  if (csvBtn) {
    csvBtn.addEventListener('click', () => exportFilteredCasesCsv());
  }

  if (dlDossierBtn) {
    dlDossierBtn.addEventListener('click', () => {
      if (!selectedCasePayload) return;
      const blob = new Blob([JSON.stringify(selectedCasePayload, null, 2)], {
        type: 'application/json;charset=utf-8',
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${selectedCasePayload.case_record.case_number}_forense.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    });
  }

  if (printBtn) {
    printBtn.addEventListener('click', () => window.print());
  }

  let debounceTimer = null;
  if (searchInput) {
    searchInput.addEventListener('input', () => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => reloadCasesList(false), 240);
    });
  }

  if (statusSelect) statusSelect.addEventListener('change', () => reloadCasesList(false));
  if (prioSelect) prioSelect.addEventListener('change', () => reloadCasesList(false));
}

async function refreshAllTelemetry() {
  const overviewRes = await ApiClient.cicpcDashboard();
  renderDashboardStats(overviewRes.data);
  await reloadCasesList(false);
  if (selectedCaseId) {
    await selectAndInspectCase(selectedCaseId);
  }
}

function renderDashboardStats(data) {
  const kpis = data.kpis || {};
  setText('kpi-total-cases', String(kpis.total_cases ?? 0));
  setText('kpi-urgent-cases', String(kpis.urgent_cases ?? 0));
  setText('kpi-affected-victims', String(kpis.affected_victims ?? 0));
  setText('kpi-pending-cases', String(kpis.pending_cases ?? 0));
  setText('kpi-analysis-cases', String(kpis.analysis_cases ?? 0));
  setText('kpi-actioned-cases', String(kpis.actioned_cases ?? 0));

  // Campaigns Table
  const tbody = document.getElementById('campaigns-table-body');
  if (tbody) {
    tbody.textContent = '';
    const campaigns = data.campaigns || [];
    campaigns.forEach((c) => {
      const tr = document.createElement('tr');

      const tdDom = document.createElement('td');
      tdDom.className = 'mono';
      tdDom.textContent = String(c.target_domain || '');

      const tdCount = document.createElement('td');
      tdCount.style.fontWeight = '700';
      tdCount.textContent = `${c.reports_count} caso(s)`;

      const tdScore = document.createElement('td');
      const scoreBadge = document.createElement('span');
      scoreBadge.className = Number(c.max_risk_score) >= 70 ? 'badge badge-critical' : 'badge badge-warning';
      scoreBadge.textContent = `${c.max_risk_score}/100`;
      tdScore.appendChild(scoreBadge);

      const tdEnt = document.createElement('td');
      tdEnt.textContent = String(c.impersonated_entity || 'En clasificación');

      const tdAct = document.createElement('td');
      tdAct.textContent =
        ACTION_LABELS[c.strategic_action_type] || String(c.strategic_action_type || '');

      tr.append(tdDom, tdCount, tdScore, tdEnt, tdAct);
      tbody.appendChild(tr);
    });
  }

  // Channel Distribution Bars
  const chContainer = document.getElementById('channels-bars-container');
  if (chContainer) {
    chContainer.textContent = '';
    const channels = data.channels || [];
    const totalCases = Math.max(1, Number(kpis.total_cases || 1));

    channels.forEach((ch) => {
      const count = Number(ch.total || 0);
      const pct = Math.min(100, Math.round((count / totalCases) * 100));

      const row = document.createElement('div');
      row.className = 'cicpc-channel-bar-row';

      const top = document.createElement('div');
      top.style.display = 'flex';
      top.style.justifyContent = 'space-between';
      top.style.fontSize = '0.84rem';

      const nameSpan = document.createElement('span');
      nameSpan.textContent = CHANNEL_LABELS[ch.channel_received] || String(ch.channel_received);

      const valSpan = document.createElement('span');
      valSpan.className = 'mono';
      valSpan.textContent = `${count} (${pct}%)`;

      top.append(nameSpan, valSpan);

      const track = document.createElement('div');
      track.className = 'cicpc-channel-track';
      const fill = document.createElement('div');
      fill.className = 'cicpc-channel-fill';
      fill.style.width = `${pct}%`;
      track.appendChild(fill);

      row.append(top, track);
      chContainer.appendChild(row);
    });
  }

  // Audit Logs Table
  const auditBody = document.getElementById('audit-logs-tbody');
  if (auditBody) {
    auditBody.textContent = '';
    (data.audit_logs || []).forEach((log) => {
      const tr = document.createElement('tr');

      const tdDate = document.createElement('td');
      tdDate.className = 'mono';
      tdDate.style.fontSize = '0.77rem';
      tdDate.textContent = String(log.created_at || '');

      const tdBadge = document.createElement('td');
      tdBadge.className = 'mono';
      tdBadge.style.color = '#F8E39C';
      tdBadge.textContent = String(log.officer_badge || '');

      const tdName = document.createElement('td');
      tdName.textContent = String(log.officer_name || '');

      const tdCode = document.createElement('td');
      tdCode.className = 'mono';
      tdCode.style.fontSize = '0.76rem';
      tdCode.textContent = String(log.action_code || '');

      const tdDetail = document.createElement('td');
      tdDetail.textContent = String(log.detail || '');

      tr.append(tdDate, tdBadge, tdName, tdCode, tdDetail);
      auditBody.appendChild(tr);
    });
  }
}

async function reloadCasesList(autoSelectFirst = false) {
  const search = document.getElementById('filter-search-input')?.value || '';
  const status = document.getElementById('filter-status-select')?.value || 'all';
  const priority = document.getElementById('filter-priority-select')?.value || 'all';

  const res = await ApiClient.cicpcListCases({ status, priority, search });
  currentCases = res.data?.cases || [];

  setText('cases-count-badge', `${currentCases.length} caso(s)`);
  const listEl = document.getElementById('cicpc-cases-list');
  if (!listEl) return;

  listEl.textContent = '';

  if (currentCases.length === 0) {
    const empty = document.createElement('div');
    empty.style.padding = '28px 14px';
    empty.style.textAlign = 'center';
    empty.style.color = '#9CC4F6';
    empty.textContent = 'No hay expedientes que coincidan con los filtros seleccionados.';
    listEl.appendChild(empty);
    return;
  }

  currentCases.forEach((c) => {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = `cicpc-case-item prio-${c.priority}${c.id === selectedCaseId ? ' selected' : ''}`;
    btn.dataset.caseId = String(c.id);

    const topRow = document.createElement('div');
    topRow.style.display = 'flex';
    topRow.style.justifyContent = 'space-between';
    topRow.style.alignItems = 'center';
    topRow.style.gap = '8px';

    const expCode = document.createElement('span');
    expCode.className = 'mono';
    expCode.style.fontSize = '0.76rem';
    expCode.style.color = '#00E1FF';
    expCode.textContent = String(c.case_number);

    const statusTag = document.createElement('span');
    statusTag.style.fontSize = '0.73rem';
    statusTag.style.color = '#F8E39C';
    statusTag.textContent = STATUS_LABELS[c.status] || String(c.status);

    topRow.append(expCode, statusTag);

    const domainLine = document.createElement('div');
    domainLine.style.fontWeight = '700';
    domainLine.style.fontSize = '0.94rem';
    domainLine.style.marginTop = '6px';
    domainLine.style.wordBreak = 'break-all';
    domainLine.textContent = String(c.target_domain);

    const subLine = document.createElement('div');
    subLine.style.fontSize = '0.8rem';
    subLine.style.color = '#C5DCFA';
    subLine.style.marginTop = '4px';
    subLine.textContent = `${c.impersonated_entity} • Riesgo ${c.risk_score}/100`;

    const footLine = document.createElement('div');
    footLine.style.display = 'flex';
    footLine.style.justifyContent = 'space-between';
    footLine.style.fontSize = '0.74rem';
    footLine.style.color = '#89B9F3';
    footLine.style.marginTop = '8px';

    const chanSpan = document.createElement('span');
    chanSpan.textContent = `${CHANNEL_LABELS[c.channel_received] || c.channel_received} • ${
      SOURCE_LABELS[c.source_type] || c.source_type
    }`;

    const timeSpan = document.createElement('span');
    timeSpan.textContent = formatRelativeTime(c.created_at);

    footLine.append(chanSpan, timeSpan);

    btn.append(topRow, domainLine, subLine, footLine);
    btn.addEventListener('click', () => selectAndInspectCase(String(c.id)));
    listEl.appendChild(btn);
  });

  if (autoSelectFirst && currentCases.length > 0 && !selectedCaseId) {
    await selectAndInspectCase(String(currentCases[0].id));
  }
}

async function selectAndInspectCase(caseId) {
  selectedCaseId = caseId;
  document.querySelectorAll('.cicpc-case-item').forEach((el) => {
    el.classList.toggle('selected', el.dataset.caseId === caseId);
  });

  const emptyEl = document.getElementById('inspector-empty-state');
  const detailEl = document.getElementById('inspector-detail-content');

  const res = await ApiClient.cicpcGetCaseDetail(caseId);
  selectedCasePayload = res.data;
  const rec = selectedCasePayload.case_record;
  const report = selectedCasePayload.forensic_report;

  if (emptyEl) emptyEl.style.display = 'none';
  if (detailEl) detailEl.style.display = 'block';

  setText('detail-case-number', rec.case_number);

  const prioBadge = document.getElementById('detail-priority-badge');
  if (prioBadge) {
    prioBadge.className =
      rec.priority === 'URGENT'
        ? 'badge badge-critical'
        : rec.priority === 'HIGH'
        ? 'badge badge-warning'
        : 'badge badge-tech';
    prioBadge.textContent = `Prioridad: ${rec.priority}`;
  }

  const impactBadge = document.getElementById('detail-impact-badge');
  if (impactBadge) {
    impactBadge.className =
      rec.incident_impact === 'PREVENTIVE' ? 'badge badge-safe' : 'badge badge-critical';
    impactBadge.textContent = IMPACT_LABELS[rec.incident_impact] || rec.incident_impact;
  }

  setText('detail-domain-title', rec.target_domain);
  setText('detail-target-url', `URL Auditada: ${rec.target_url}`);
  setText('detail-entity', rec.impersonated_entity || 'No especificada');
  setText('detail-channel', CHANNEL_LABELS[rec.channel_received] || rec.channel_received);
  setText('detail-suspect', rec.suspect_contact || 'No suministrado');
  setText('detail-source-type', SOURCE_LABELS[rec.source_type] || rec.source_type);
  setText(
    'detail-reporter-contact',
    rec.reporter_contact || rec.reporter_alias || 'Reporte ciudadano anónimo'
  );
  setText('detail-risk-score', `${rec.risk_score}/100 (${rec.risk_level})`);
  setText(
    'detail-statement',
    rec.citizen_statement || 'Sin relato adicional suministrado por el usuario.'
  );

  // Forensic Findings & Source Lines
  setText('detail-sha256', report ? `SHA-256: ${report.integrity_sha256}` : '');
  setText(
    'detail-transport-summary',
    report
      ? `Protocolo ${(report.transport_audit?.protocol || '').toUpperCase()} | HTTP ${
          report.transport_audit?.http_status_code || 200
        } | Redirecciones: ${report.transport_audit?.redirect_count ?? 0}`
      : ''
  );

  const findingsBox = document.getElementById('detail-findings-box');
  if (findingsBox) {
    findingsBox.textContent = '';

    if (report?.phishing_forensics?.executed) {
      const pf = report.phishing_forensics;
      const dossierCard = document.createElement('div');
      dossierCard.className = 'cicpc-meta-box';
      dossierCard.style.borderLeft = '3px solid #00E1FF';
      dossierCard.style.marginBottom = '12px';

      const dHead = document.createElement('div');
      dHead.className = 'mono';
      dHead.style.fontSize = '0.8rem';
      dHead.style.color = '#00E1FF';
      dHead.textContent = 'INTELIGENCIA FORENSE: HOSTING • WHOIS • DESTINOS • CONSULTAS cURL';

      const dSummary = document.createElement('div');
      dSummary.style.marginTop = '6px';
      dSummary.style.fontSize = '0.86rem';
      dSummary.style.whiteSpace = 'pre-wrap';
      const ips = (pf.hosting_intel?.ip_addresses || []).join(', ') || 'N/A';
      const destList = (pf.exfiltration_destinations || [])
        .map(
          (d) =>
            `• [${d.is_same_server ? 'MISMO SERVIDOR' : d.destination_type}] ${d.http_method} ${d.destination_url} (${d.repository_or_collector_id})`
        )
        .join('\n');
      dSummary.textContent = [
        `Hosting: ${pf.hosting_intel?.hosting_provider} | IP: ${ips} | ${pf.hosting_intel?.asn} | País: ${pf.hosting_intel?.country}`,
        `WHOIS: ${pf.whois_rdap?.registrar_name} | Creación: ${pf.whois_rdap?.creation_date || 'N/A'} (Edad: ${pf.whois_rdap?.domain_age_days ?? 'N/A'} días) | Abuse: ${pf.whois_rdap?.abuse_contact_email || 'N/A'}`,
        ...(destList ? [`Destinos de exfiltración:\n${destList}`] : []),
      ].join('\n');

      dossierCard.append(dHead, dSummary);

      if (pf.curl_inspections && pf.curl_inspections.length > 0) {
        const curlPre = document.createElement('pre');
        curlPre.className = 'mono';
        curlPre.style.marginTop = '8px';
        curlPre.style.padding = '8px';
        curlPre.style.background = '#010818';
        curlPre.style.borderRadius = '6px';
        curlPre.style.fontSize = '0.75rem';
        curlPre.style.color = '#A5F3FC';
        curlPre.style.overflowX = 'auto';
        curlPre.textContent = pf.curl_inspections
          .map(
            (c) =>
              `$ ${c.curl_command}\n${c.http_status_line}\n${c.body_excerpt}\n-> ${c.forensic_conclusion}`
          )
          .join('\n\n');
        dossierCard.appendChild(curlPre);
      }

      findingsBox.appendChild(dossierCard);
    }

    const findings = report?.findings || [];
    if (findings.length === 0) {
      const p = document.createElement('p');
      p.style.color = '#9CC4F6';
      p.textContent = 'Sin hallazgos de código adicionales registrados en este escaneo.';
      findingsBox.appendChild(p);
    } else {
      findings.forEach((f) => {
        const card = document.createElement('div');
        card.className = 'cicpc-meta-box';
        card.style.borderLeft = '3px solid #FF2E4C';

        const head = document.createElement('div');
        head.className = 'mono';
        head.style.fontSize = '0.78rem';
        head.style.color = '#00E1FF';
        head.textContent = `[${f.severity}] ${f.rule_code} • Selector: ${f.dom_selector} (Línea ${f.line_number})`;

        const tech = document.createElement('div');
        tech.style.marginTop = '4px';
        tech.style.fontSize = '0.87rem';
        tech.textContent = f.technical_detail;

        const code = document.createElement('div');
        code.className = 'mono';
        code.style.marginTop = '6px';
        code.style.padding = '6px 8px';
        code.style.background = '#010818';
        code.style.borderRadius = '6px';
        code.style.fontSize = '0.78rem';
        code.style.color = '#FCA5A5';
        code.style.overflowX = 'auto';
        code.textContent = f.code_snippet;

        card.append(head, tech, code);
        findingsBox.appendChild(card);
      });
    }
  }

  const linesBox = document.getElementById('detail-source-lines');
  if (linesBox) {
    linesBox.textContent = '';
    (report?.source_preview || []).forEach((lineObj) => {
      const row = document.createElement('div');
      row.className = lineObj.has_finding ? 'code-line-row flagged' : 'code-line-row';

      const num = document.createElement('span');
      num.className = 'code-line-num';
      num.textContent = String(lineObj.line);

      const txt = document.createElement('span');
      txt.className = 'code-line-text';
      txt.textContent = String(lineObj.content);

      row.append(num, txt);
      linesBox.appendChild(row);
    });
  }

  // Populate Decision Form
  const statusSel = document.getElementById('decision-status');
  const prioSel = document.getElementById('decision-priority');
  const actionSel = document.getElementById('decision-action');
  const notesArea = document.getElementById('decision-notes');

  if (statusSel) statusSel.value = rec.status || 'pending';
  if (prioSel) prioSel.value = rec.priority || 'HIGH';
  if (actionSel) actionSel.value = rec.strategic_action_type || 'NONE';
  if (notesArea) notesArea.value = rec.expert_notes || '';

  setText(
    'detail-last-reviewed',
    rec.reviewed_by_badge
      ? `Última revisión: ${rec.reviewed_by_name} (${rec.reviewed_by_badge})`
      : 'Expediente pendiente de primera revisión experta'
  );
}

function bindDecisionForm() {
  const form = document.getElementById('cicpc-decision-form');
  const submitBtn = document.getElementById('decision-submit-btn');
  if (!form) return;

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!selectedCaseId) return;
    if (submitBtn) submitBtn.disabled = true;

    try {
      const payload = {
        status: document.getElementById('decision-status')?.value || 'in_analysis',
        priority: document.getElementById('decision-priority')?.value || 'HIGH',
        strategic_action_type: document.getElementById('decision-action')?.value || 'NONE',
        expert_notes: document.getElementById('decision-notes')?.value || '',
      };

      const res = await ApiClient.cicpcUpdateCase(selectedCaseId, payload);
      showToast(res.message || 'Dictamen guardado exitosamente.');
      await refreshAllTelemetry();
    } catch (err) {
      showToast(err.message || 'No se pudo actualizar el expediente.', true);
    } finally {
      if (submitBtn) submitBtn.disabled = false;
    }
  });
}

function exportFilteredCasesCsv() {
  if (!currentCases.length) {
    showToast('No hay expedientes para exportar.', true);
    return;
  }

  const headers = [
    'Expediente',
    'Prioridad',
    'Estado',
    'Dominio',
    'URL',
    'Puntaje_Riesgo',
    'Canal',
    'Entidad_Suplantada',
    'Remitente_Sospechoso',
    'Impacto',
    'Accion_Estrategica',
    'Revisado_Por',
    'Fecha_UTC',
  ];

  const escapeCsv = (val) => `"${String(val ?? '').replace(/"/g, '""')}"`;
  const lines = [headers.join(',')];

  currentCases.forEach((c) => {
    lines.push(
      [
        c.case_number,
        c.priority,
        c.status,
        c.target_domain,
        c.target_url,
        c.risk_score,
        c.channel_received,
        c.impersonated_entity,
        c.suspect_contact,
        c.incident_impact,
        c.strategic_action_type,
        c.reviewed_by_badge || '',
        c.created_at,
      ]
        .map(escapeCsv)
        .join(',')
    );
  });

  const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `inteligencia_estrategica_cicpc_${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

async function exportSuricataIdsRules(btn) {
  if (btn) btn.disabled = true;
  try {
    const res = await ApiClient.cicpcExportSuricataRules();
    const rulesText = res?.data?.rules_text || '';
    const filename = res?.data?.filename || 'antiphishing_d360_cicpc.rules';

    if (!rulesText) {
      showToast('No hay indicadores activos para generar reglas Suricata.', true);
      return;
    }

    const blob = new Blob([rulesText], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);

    showToast(`Firmas Suricata IDS/IPS exportadas (${res.data.total_cases_included} casos).`);
    await refreshAllTelemetry();
  } catch (err) {
    showToast(err.message || 'No se pudieron generar las reglas Suricata.', true);
  } finally {
    if (btn) btn.disabled = false;
  }
}

function setText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}
