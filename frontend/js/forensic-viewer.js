import {
  ApiClient,
  initMobileNavbar,
  setPendingScanId,
  showToast,
  syncNavbarAuth,
} from './api-client.js';
import { ExportService } from './export-service.js';
import { initPwaSupport } from './pwa-install.js';
import {
  buildVerdictSpeechScript,
  isAutoVoiceEnabled,
  isSeniorModeActive,
  speakTextAloud,
} from './senior-shield.js';

let loadedReport = null;
let activeUser = null;

document.addEventListener('DOMContentLoaded', async () => {
  initMobileNavbar();
  initPwaSupport();
  activeUser = await syncNavbarAuth();

  const scanId = extractScanIdFromUrl();
  if (!scanId) {
    renderReportError('No se especificó un código de reporte válido.');
    return;
  }

  await fetchAndRenderReport(scanId);
});

function extractScanIdFromUrl() {
  const qs = new URLSearchParams(window.location.search);
  const fromQuery = qs.get('id') || qs.get('scan_id');
  if (fromQuery) return fromQuery.trim();

  // Match /scan/scn_...
  const parts = window.location.pathname.split('/').filter(Boolean);
  if (parts.length >= 2 && parts[0] === 'scan' && parts[1] !== 'new') {
    return decodeURIComponent(parts[1]);
  }
  return '';
}

async function fetchAndRenderReport(scanId) {
  const loadingBox = document.getElementById('report-loading');
  const contentBox = document.getElementById('report-content');

  try {
    const res = await ApiClient.getScanById(scanId);
    loadedReport = res.data;

    if (!activeUser) {
      setPendingScanId(loadedReport.scan_id);
    }

    if (loadingBox) loadingBox.style.display = 'none';
    if (contentBox) contentBox.style.display = 'block';

    populateVerdictBanner(loadedReport);
    populateConversionPrompt(loadedReport);
    populateDeepAuditSection(loadedReport);
    populatePhishingForensicsSection(loadedReport);
    populateFindingsList(loadedReport);
    populateSourceViewer(loadedReport);
    bindReportActions(loadedReport);
    initCicpcReportModal(loadedReport);
  } catch (err) {
    renderReportError(
      err.message || 'No encontramos el reporte solicitado. Puede que el enlace haya expirado.'
    );
  }
}

function renderReportError(msg) {
  const loadingBox = document.getElementById('report-loading');
  const errBox = document.getElementById('report-error');
  if (loadingBox) loadingBox.style.display = 'none';
  if (errBox) {
    errBox.style.display = 'block';
    const msgEl = document.getElementById('report-error-msg');
    if (msgEl) msgEl.textContent = msg;
  }
}

function populateVerdictBanner(report) {
  const banner = document.getElementById('verdict-banner');
  if (banner) {
    banner.className = `verdict-hero-banner risk-${report.risk_level}`;
  }

  // Update circular SVG gauge
  const scoreValEl = document.getElementById('gauge-score-val');
  const circleArc = document.getElementById('gauge-progress-arc');
  if (scoreValEl) scoreValEl.textContent = String(report.risk_score);

  if (circleArc) {
    const circumference = 314; // 2 * pi * 50
    const offset = circumference - (Math.min(100, Math.max(0, report.risk_score)) / 100) * circumference;
    circleArc.style.strokeDashoffset = String(offset);
    circleArc.style.stroke =
      report.risk_level === 'CRITICAL'
        ? '#EF4444'
        : report.risk_level === 'WARNING'
        ? '#F59E0B'
        : '#10B981';
  }

  const badgeEl = document.getElementById('verdict-level-badge');
  if (badgeEl) {
    badgeEl.className =
      report.risk_level === 'CRITICAL'
        ? 'badge badge-critical'
        : report.risk_level === 'WARNING'
        ? 'badge badge-warning'
        : 'badge badge-safe';
    badgeEl.textContent = '';

    const led = document.createElement('span');
    led.className =
      report.risk_level === 'CRITICAL'
        ? 'status-led critical'
        : report.risk_level === 'WARNING'
        ? 'status-led warning'
        : 'status-led safe';

    const labelSpan = document.createElement('span');
    labelSpan.textContent =
      report.risk_level === 'CRITICAL'
        ? 'Riesgo Crítico — No entregues tus datos'
        : report.risk_level === 'WARNING'
        ? 'Precaución — Faltan medidas de seguridad'
        : 'Sitio Seguro y Cifrado';

    badgeEl.append(led, labelSpan);
  }

  const titleEl = document.getElementById('verdict-title');
  if (titleEl) titleEl.textContent = report.citizen_verdict?.title || '';

  const summaryEl = document.getElementById('verdict-summary');
  if (summaryEl) summaryEl.textContent = report.citizen_verdict?.summary || '';

  const targetUrlEl = document.getElementById('verdict-target-url');
  if (targetUrlEl) targetUrlEl.textContent = report.target_url;

  const stepsList = document.getElementById('verdict-steps-list');
  if (stepsList) {
    stepsList.textContent = '';
    (report.citizen_verdict?.action_steps || []).forEach((step) => {
      const li = document.createElement('li');
      li.appendChild(document.createTextNode(step));
      stepsList.appendChild(li);
    });
  }
}

function populateConversionPrompt(report) {
  const box = document.getElementById('anon-conversion-banner');
  const regBtn = document.getElementById('anon-save-report-btn');
  if (!box) return;

  if (!activeUser) {
    box.style.display = 'flex';
    if (regBtn) {
      regBtn.href = `/register?pending_scan_id=${encodeURIComponent(report.scan_id)}`;
    }
  } else {
    box.style.display = 'none';
  }
}

function populateDeepAuditSection(report) {
  const section = document.getElementById('deep-audit-grid-section');
  if (!section) return;

  const linkFn = report.link_functionality;
  const vis = report.visual_brand_audit;
  if (!linkFn && !vis) {
    section.style.display = 'none';
    return;
  }

  section.style.display = 'grid';
  section.textContent = '';

  if (linkFn) {
    const card = document.createElement('article');
    card.className = 'deep-audit-report-card';

    const badge = document.createElement('span');
    badge.className =
      linkFn.functionality_status === 'CLOAKED_CLIENT_REDIRECT' ||
      (linkFn.exfiltration_endpoints && linkFn.exfiltration_endpoints.length > 0)
        ? 'badge badge-critical'
        : linkFn.reachable
        ? 'badge badge-tech'
        : 'badge badge-warning';
    badge.textContent = linkFn.reachable
      ? `Funcionalidad del Enlace: ACTIVO (HTTP ${linkFn.http_status_code} • ${linkFn.response_time_ms} ms)`
      : 'Funcionalidad del Enlace: INACTIVO / DADO DE BAJA';

    const title = document.createElement('h3');
    title.style.marginTop = '10px';
    title.style.fontSize = '1.08rem';
    title.textContent = 'Conexión en Vivo de Verificación del Link';

    const desc = document.createElement('p');
    desc.style.marginTop = '6px';
    desc.style.color = '#E2E8F0';
    desc.style.fontSize = '0.92rem';
    desc.textContent = linkFn.summary || '';

    const metaList = document.createElement('div');
    metaList.className = 'deep-audit-report-meta mono';
    metaList.textContent = `Destino final: ${linkFn.resolved_final_url} | Saltos: ${linkFn.redirect_hops} | Bundles JS revisados: ${linkFn.spa_bundles_inspected}`;

    card.append(badge, title, desc, metaList);

    if (linkFn.exfiltration_endpoints && linkFn.exfiltration_endpoints.length > 0) {
      const exfilBox = document.createElement('div');
      exfilBox.className = 'deep-audit-report-alert mono';
      exfilBox.textContent = `Receptor malicioso activo: ${linkFn.exfiltration_endpoints.join(' | ')}`;
      card.appendChild(exfilBox);
    }

    section.appendChild(card);
  }

  if (vis) {
    const isImpostor = vis.is_official_bank_page === false;
    const isOfficial = vis.is_official_bank_page === true;

    const card = document.createElement('article');
    card.className = isImpostor
      ? 'deep-audit-report-card impostor'
      : 'deep-audit-report-card';

    const badge = document.createElement('span');
    badge.className = isImpostor
      ? 'badge badge-critical'
      : isOfficial
      ? 'badge badge-safe'
      : 'badge badge-tech';
    badge.textContent = vis.verdict_label || 'Auditoría de Imágenes Bancarias';

    const title = document.createElement('h3');
    title.style.marginTop = '10px';
    title.style.fontSize = '1.08rem';
    title.textContent = 'Comparación de Imágenes e Identidad Bancaria';

    const desc = document.createElement('p');
    desc.style.marginTop = '6px';
    desc.style.color = '#E2E8F0';
    desc.style.fontSize = '0.92rem';
    desc.textContent = vis.verdict_summary || '';

    const metaList = document.createElement('div');
    metaList.className = 'deep-audit-report-meta mono';
    const instTxt = vis.detected_institution || 'Ninguna entidad reclamada';
    const officialTxt = vis.official_domain_expected || 'N/A';
    metaList.textContent = `Entidad: ${instTxt} | Dominio oficial esperado: ${officialTxt} | Imágenes revisadas: ${vis.images_inspected_count}`;

    card.append(badge, title, desc, metaList);

    if (vis.matched_assets && vis.matched_assets.length > 0) {
      vis.matched_assets.forEach((asset) => {
        const assetLine = document.createElement('div');
        assetLine.className = 'deep-audit-report-alert mono';
        assetLine.textContent = `[${asset.asset_type}] ${asset.match_method} (${asset.similarity_percent}% similitud • SHA256:${asset.sha256_prefix}) -> ${asset.asset_url}`;
        card.appendChild(assetLine);
      });
    }

    section.appendChild(card);
  }
}

function populatePhishingForensicsSection(report) {
  const section = document.getElementById('phishing-forensics-dossier-section');
  if (!section) return;

  const pf = report.phishing_forensics;
  if (!pf || !pf.executed) {
    section.style.display = 'none';
    return;
  }

  section.style.display = 'block';
  section.textContent = '';

  const titleRow = document.createElement('div');
  titleRow.style.marginBottom = '14px';

  const badge = document.createElement('span');
  badge.className = pf.is_phishing_or_suspicious ? 'badge badge-critical' : 'badge badge-tech';
  badge.textContent = 'Inteligencia Forense de Infraestructura y Exfiltración';

  const h2 = document.createElement('h2');
  h2.style.fontSize = '1.42rem';
  h2.style.marginTop = '8px';
  h2.textContent = 'Análisis Forense: Hosting, Registros WHOIS, Destinos y Consultas cURL';

  const execSummary = document.createElement('p');
  execSummary.style.marginTop = '6px';
  execSummary.style.color = '#CBD5E1';
  execSummary.style.fontSize = '0.94rem';
  execSummary.textContent = pf.executive_summary || '';

  titleRow.append(badge, h2, execSummary);
  section.appendChild(titleRow);

  // 1 & 2. Hosting + WHOIS Grid
  const topGrid = document.createElement('div');
  topGrid.className = 'deep-audit-grid';
  topGrid.style.marginTop = '12px';

  if (pf.hosting_intel) {
    const h = pf.hosting_intel;
    const hCard = document.createElement('article');
    hCard.className = 'deep-audit-report-card';

    const hTag = document.createElement('span');
    hTag.className = 'badge badge-tech';
    hTag.textContent = '1. Hosting, Red, DNS y Servidor';

    const hTitle = document.createElement('h3');
    hTitle.style.marginTop = '10px';
    hTitle.style.fontSize = '1.08rem';
    hTitle.textContent = h.hosting_provider;

    const hDesc = document.createElement('p');
    hDesc.style.marginTop = '6px';
    hDesc.style.fontSize = '0.9rem';
    hDesc.style.color = '#E2E8F0';
    hDesc.textContent = h.infrastructure_notes || '';

    const hMeta = document.createElement('div');
    hMeta.className = 'deep-audit-report-meta mono';
    const ips = (h.ip_addresses || []).join(', ') || 'Sin registro A';
    const ipv6 = h.ipv6_addresses && h.ipv6_addresses.length > 0 ? ` | IPv6: ${h.ipv6_addresses[0]}` : '';
    const ns = (h.nameservers || []).join(', ') || 'N/A';
    const cdn = h.cdn_or_waf_behind ? `\nCDN / Proxy: ${h.cdn_or_waf_behind}` : '';
    hMeta.style.whiteSpace = 'pre-wrap';
    hMeta.textContent = `Host: ${h.queried_host}\nIPv4: ${ips}${ipv6}\nASN: ${h.asn}\nISP / Org: ${h.isp_organization}\nUbicación: ${h.country} (${h.region_city})\nServidor HTTP: ${h.server_software}\nNameservers: ${ns}${cdn}`;

    hCard.append(hTag, hTitle, hDesc, hMeta);
    topGrid.appendChild(hCard);
  }

  if (pf.whois_rdap) {
    const w = pf.whois_rdap;
    const wCard = document.createElement('article');
    const isFreshDomain = w.domain_age_days !== null && w.domain_age_days <= 30;
    wCard.className = isFreshDomain ? 'deep-audit-report-card impostor' : 'deep-audit-report-card';

    const wTag = document.createElement('span');
    wTag.className = isFreshDomain ? 'badge badge-critical' : 'badge badge-tech';
    wTag.textContent =
      w.domain_age_days !== null
        ? `2. Registro WHOIS / RDAP (Edad: ${w.domain_age_days} días)`
        : '2. Registro WHOIS / RDAP';

    const wTitle = document.createElement('h3');
    wTitle.style.marginTop = '10px';
    wTitle.style.fontSize = '1.08rem';
    wTitle.textContent = `Registrador: ${w.registrar_name}`;

    const wDesc = document.createElement('p');
    wDesc.style.marginTop = '6px';
    wDesc.style.fontSize = '0.9rem';
    wDesc.style.color = '#E2E8F0';
    wDesc.textContent = w.forensic_assessment || '';

    const wMeta = document.createElement('div');
    wMeta.className = 'deep-audit-report-meta mono';
    wMeta.style.whiteSpace = 'pre-wrap';
    wMeta.textContent = [
      `Dominio Raíz: ${w.queried_domain}`,
      `Fuente: ${w.lookup_source}`,
      `Creación: ${w.creation_date || 'No publicada por registro TLD'}`,
      `Expiración: ${w.expiration_date || 'N/A'}`,
      `Titular / Org: ${w.registrant_organization}`,
      `Abuse Email (Takedown): ${w.abuse_contact_email || 'N/A'}${
        w.abuse_contact_phone ? ` • Tel: ${w.abuse_contact_phone}` : ''
      }`,
      `Estados ICANN: ${(w.domain_status || []).join(', ') || 'N/A'}`,
    ].join('\n');

    wCard.append(wTag, wTitle, wDesc, wMeta);

    if (w.raw_whois_lines && w.raw_whois_lines.length > 0) {
      const det = document.createElement('details');
      det.className = 'finding-tech-accordion';
      const sum = document.createElement('summary');
      sum.textContent = 'Ver salida cruda WHOIS / RDAP';
      const pre = document.createElement('pre');
      pre.className = 'forensic-report-curl-pre mono';
      pre.textContent = w.raw_whois_lines.join('\n');
      det.append(sum, pre);
      wCard.appendChild(det);
    }

    topGrid.appendChild(wCard);
  }

  section.appendChild(topGrid);

  // 3. Repositories & Exfiltration Destinations Card
  const destPanel = document.createElement('article');
  destPanel.className = 'deep-audit-report-card';
  destPanel.style.marginTop = '16px';

  const destBadge = document.createElement('span');
  destBadge.className =
    pf.exfiltration_destinations && pf.exfiltration_destinations.length > 0
      ? 'badge badge-critical'
      : 'badge badge-tech';
  destBadge.textContent = '3. Repositorios y Destinos de Exfiltración';

  const destHeading = document.createElement('h3');
  destHeading.style.marginTop = '10px';
  destHeading.style.fontSize = '1.1rem';
  destHeading.textContent =
    'Análisis Minucioso de Destinos donde la Página Envía o Sincroniza la Información';

  destPanel.append(destBadge, destHeading);

  if (!pf.exfiltration_destinations || pf.exfiltration_destinations.length === 0) {
    const emptyP = document.createElement('p');
    emptyP.style.marginTop = '8px';
    emptyP.style.color = '#94A3B8';
    emptyP.textContent =
      'No se detectaron formularios activos ni webhooks externos de captura de datos en el documento inspeccionado.';
    destPanel.appendChild(emptyP);
  } else {
    pf.exfiltration_destinations.forEach((d) => {
      const box = document.createElement('div');
      box.className = 'forensic-report-dest-item';

      const top = document.createElement('div');
      top.style.display = 'flex';
      top.style.flexWrap = 'wrap';
      top.style.gap = '8px';
      top.style.alignItems = 'center';

      const relBadge = document.createElement('span');
      relBadge.className = d.is_same_server ? 'badge badge-warning' : 'badge badge-critical';
      relBadge.textContent = d.is_same_server
        ? `ARCHIVO EN EL MISMO SERVIDOR • ${d.http_method}`
        : `${d.destination_type} • ${d.http_method}`;

      const locSpan = document.createElement('span');
      locSpan.className = 'mono';
      locSpan.style.fontSize = '0.78rem';
      locSpan.style.color = '#94A3B8';
      locSpan.textContent = d.source_location;

      top.append(relBadge, locSpan);

      const urlDiv = document.createElement('div');
      urlDiv.className = 'mono';
      urlDiv.style.marginTop = '8px';
      urlDiv.style.color = '#00E1FF';
      urlDiv.style.fontSize = '0.84rem';
      urlDiv.style.wordBreak = 'break-all';
      urlDiv.textContent = d.destination_url;

      const expP = document.createElement('p');
      expP.style.marginTop = '6px';
      expP.style.fontSize = '0.88rem';
      expP.style.color = '#F1F5F9';
      expP.textContent = d.forensic_detail;

      const metaDiv = document.createElement('div');
      metaDiv.className = 'deep-audit-report-meta mono';
      const fieldsStr = (d.captured_fields || []).join(', ') || 'N/A';
      metaDiv.textContent = `Identificador / Repositorio: ${d.repository_or_collector_id} | Campos enviados: [${fieldsStr}] | Red receptora: ${
        d.resolved_ip_and_asn || 'Mismo host'
      }`;

      box.append(top, urlDiv, expP, metaDiv);
      destPanel.appendChild(box);
    });
  }

  section.appendChild(destPanel);

  // 4. Terminal Results of cURL Queries on Same-Server Files & Related Endpoints
  if (pf.curl_inspections && pf.curl_inspections.length > 0) {
    const curlPanel = document.createElement('article');
    curlPanel.className = 'deep-audit-report-card';
    curlPanel.style.marginTop = '16px';

    const curlBadge = document.createElement('span');
    curlBadge.className = 'badge badge-tech';
    curlBadge.textContent = '4. Evidencia de Consultas cURL';

    const curlHeading = document.createElement('h3');
    curlHeading.style.marginTop = '10px';
    curlHeading.style.fontSize = '1.1rem';
    curlHeading.textContent =
      'Resultados de Consultas cURL sobre Archivos del Mismo Servidor y Destinos Relacionados';

    curlPanel.append(curlBadge, curlHeading);

    pf.curl_inspections.forEach((c) => {
      const termWrap = document.createElement('div');
      termWrap.className = 'forensic-report-curl-wrap';

      const hdr = document.createElement('div');
      hdr.className = 'forensic-report-curl-hdr mono';
      hdr.textContent = `${
        c.is_same_server ? '[MISMO SERVIDOR]' : '[RECEPTOR EXTERNO]'
      } ${c.target_role} • Estado HTTP ${c.status_code} • ${c.response_time_ms} ms`;

      const pre = document.createElement('pre');
      pre.className = 'forensic-report-curl-pre mono';
      const rawHdrs = (c.response_headers || []).map((h) => `${h.name}: ${h.value}`).join('\n');
      pre.textContent = [
        `$ ${c.curl_command}`,
        c.http_status_line,
        ...(rawHdrs ? [rawHdrs] : []),
        '',
        c.body_excerpt || '(Cuerpo vacío)',
      ].join('\n');

      const foot = document.createElement('div');
      foot.className = c.directory_listing_exposed
        ? 'deep-audit-report-alert mono'
        : 'deep-audit-report-meta';
      foot.textContent = `Conclusión Forense cURL: ${c.forensic_conclusion}`;

      termWrap.append(hdr, pre, foot);
      curlPanel.appendChild(termWrap);
    });

    section.appendChild(curlPanel);
  }
}

function populateFindingsList(report) {
  const container = document.getElementById('findings-list-container');
  const countEl = document.getElementById('findings-count-label');
  if (!container) return;

  container.textContent = '';
  const findings = report.findings || [];

  if (countEl) {
    countEl.textContent =
      findings.length === 0
        ? '0 infracciones detectadas'
        : `${findings.length} hallazgo(s) detectado(s) por Rayos X`;
  }

  if (findings.length === 0) {
    const cleanCard = document.createElement('div');
    cleanCard.className = 'finding-card';
    cleanCard.style.borderLeft = '4px solid #10B981';

    const title = document.createElement('h3');
    title.textContent = 'Sin trampas ni formularios inseguros detectados';
    const desc = document.createElement('p');
    desc.className = 'finding-citizen-text';
    desc.textContent =
      'Revisamos el candado HTTPS, los formularios y los scripts de esta página y no encontramos envíos ocultos hacia servidores externos.';

    cleanCard.append(title, desc);
    container.appendChild(cleanCard);
    return;
  }

  findings.forEach((f) => {
    const card = document.createElement('article');
    card.className = `finding-card sev-${f.severity}`;

    const topRow = document.createElement('div');
    topRow.style.display = 'flex';
    topRow.style.justifyContent = 'space-between';
    topRow.style.alignItems = 'center';
    topRow.style.flexWrap = 'wrap';
    topRow.style.gap = '8px';

    const sevBadge = document.createElement('span');
    sevBadge.className =
      f.severity === 'CRITICAL' || f.severity === 'HIGH'
        ? 'badge badge-critical'
        : 'badge badge-warning';
    sevBadge.textContent = `Severidad: ${f.severity} • Línea ${f.line_number}`;

    const catSpan = document.createElement('span');
    catSpan.className = 'mono';
    catSpan.style.fontSize = '0.8rem';
    catSpan.style.color = '#94A3B8';
    catSpan.textContent = f.dom_selector;

    topRow.append(sevBadge, catSpan);

    // Everyday Citizen Explanation
    const citizenP = document.createElement('p');
    citizenP.className = 'finding-citizen-text';
    citizenP.appendChild(document.createTextNode(f.citizen_explanation));

    // Collapsible Technical Evidence Accordion (100% createTextNode)
    const details = document.createElement('details');
    details.className = 'finding-tech-accordion';

    const summary = document.createElement('summary');
    summary.textContent = `Ver evidencia técnica forense (${f.rule_code})`;

    const techGrid = document.createElement('div');
    techGrid.className = 'finding-tech-grid';

    const detailLine = document.createElement('div');
    detailLine.appendChild(document.createTextNode(`Detalle técnico: ${f.technical_detail}`));

    const locLine = document.createElement('div');
    locLine.className = 'mono';
    locLine.appendChild(
      document.createTextNode(
        `Ubicación exacta: Selector "${f.dom_selector}" — Línea ${f.line_number}, Columna ${f.column_number}`
      )
    );

    const snippetPre = document.createElement('div');
    snippetPre.className = 'mono';
    snippetPre.style.padding = '8px 10px';
    snippetPre.style.backgroundColor = '#020617';
    snippetPre.style.borderRadius = '6px';
    snippetPre.style.color = '#FCA5A5';
    snippetPre.style.overflowX = 'auto';
    snippetPre.appendChild(document.createTextNode(f.code_snippet));

    techGrid.append(detailLine, locLine, snippetPre);
    details.append(summary, techGrid);

    card.append(topRow, citizenP, details);
    container.appendChild(card);
  });
}

function populateSourceViewer(report) {
  const hashEl = document.getElementById('source-integrity-hash');
  const linesContainer = document.getElementById('source-lines-container');
  const transportMetaEl = document.getElementById('source-transport-meta');

  if (hashEl) {
    hashEl.textContent = `SHA-256: ${report.integrity_sha256}`;
  }

  if (transportMetaEl) {
    const t = report.transport_audit;
    transportMetaEl.textContent = `Protocolo: ${(t?.protocol || '').toUpperCase()} | Redirecciones: ${
      t?.redirect_count ?? 0
    } | Duración: ${report.duration_ms}ms`;
  }

  if (!linesContainer) return;
  linesContainer.textContent = '';

  const previewLines = report.source_preview || [];
  previewLines.forEach((entry) => {
    const row = document.createElement('div');
    row.className = entry.has_finding ? 'code-line-row flagged' : 'code-line-row';

    const numSpan = document.createElement('span');
    numSpan.className = 'code-line-num';
    numSpan.appendChild(document.createTextNode(String(entry.line)));

    const codeSpan = document.createElement('span');
    codeSpan.className = 'code-line-text';
    // Strictly textNode to neutralize any HTML/JS XSS in audited pages
    codeSpan.appendChild(document.createTextNode(entry.content));

    row.append(numSpan, codeSpan);

    if (entry.has_finding) {
      const tag = document.createElement('span');
      tag.className = 'code-line-tag';
      tag.textContent = 'INFRACCIÓN DETECTADA';
      row.appendChild(tag);
    }

    linesContainer.appendChild(row);
  });
}

function bindReportActions(report) {
  if (isSeniorModeActive()) {
    document.documentElement.classList.add('senior-mode');
  }
  if (isAutoVoiceEnabled()) {
    speakTextAloud(buildVerdictSpeechScript(report));
  }

  const btnSpeak = document.getElementById('btn-speak-report');
  const btnPdf = document.getElementById('btn-export-pdf');
  const btnJson = document.getElementById('btn-export-json');
  const btnWa = document.getElementById('btn-share-whatsapp');
  const btnCopy = document.getElementById('btn-copy-summary');
  const btnCommunity = document.getElementById('btn-report-community');

  if (btnSpeak) btnSpeak.onclick = () => speakTextAloud(buildVerdictSpeechScript(report));

  if (btnPdf) btnPdf.onclick = () => ExportService.printPdfReport();
  if (btnJson) btnJson.onclick = () => ExportService.downloadJsonEvidence(report);
  if (btnWa) btnWa.onclick = () => ExportService.shareOnWhatsApp(report);
  if (btnCopy) btnCopy.onclick = () => ExportService.copyAlertSummary(report);

  if (btnCommunity) {
    if (report.risk_score >= 70) {
      btnCommunity.style.display = 'inline-flex';
      btnCommunity.onclick = async () => {
        if (!activeUser) {
          showToast('Crea tu cuenta gratuita en 20 segundos para alertar a la comunidad.');
          setTimeout(() => {
            window.location.href = `/register?pending_scan_id=${encodeURIComponent(report.scan_id)}`;
          }, 900);
          return;
        }

        btnCommunity.disabled = true;
        try {
          const res = await ApiClient.publishCommunityAlert({
            scan_id: report.scan_id,
            channel_received: 'whatsapp',
          });
          showToast(res.message);
          btnCommunity.textContent = '✓ Publicado en el Muro';
        } catch (err) {
          showToast(err.message || 'No se pudo publicar la alerta.', true);
          btnCommunity.disabled = false;
        }
      };
    } else {
      btnCommunity.style.display = 'none';
    }
  }

  // 1-click Citizen Clarity Survey (KPI #6)
  const voteYes = document.getElementById('clarity-vote-yes');
  const voteNo = document.getElementById('clarity-vote-no');
  const surveyMsg = document.getElementById('clarity-survey-msg');

  const handleVote = async (isClear) => {
    if (voteYes) voteYes.disabled = true;
    if (voteNo) voteNo.disabled = true;
    try {
      const res = await ApiClient.sendClarityFeedback(report.scan_id, isClear);
      if (surveyMsg) surveyMsg.textContent = res.message;
    } catch {
      if (surveyMsg) surveyMsg.textContent = '¡Gracias por tu calificación!';
    }
  };

  if (voteYes) voteYes.onclick = () => handleVote(true);
  if (voteNo) voteNo.onclick = () => handleVote(false);
}

function initCicpcReportModal(report) {
  const openBtn = document.getElementById('btn-report-cicpc');
  const modal = document.getElementById('cicpc-report-modal');
  const closeBtn = document.getElementById('cicpc-modal-close');
  const form = document.getElementById('cicpc-citizen-form');
  const submitBtn = document.getElementById('cicpc-submit-btn');
  const confirmBox = document.getElementById('cicpc-report-confirmation');
  const contactInput = document.getElementById('cicpc-contact');

  if (!modal || !form) return;

  if (activeUser && contactInput && !contactInput.value) {
    contactInput.value = activeUser.email || '';
  }

  const openModal = () => {
    modal.classList.add('open');
  };

  const closeModal = () => {
    modal.classList.remove('open');
  };

  if (openBtn) openBtn.onclick = openModal;
  if (closeBtn) closeBtn.onclick = closeModal;
  modal.addEventListener('click', (e) => {
    if (e.target === modal) closeModal();
  });

  // Auto-open if citizen clicked "Notificar al C.I.C.P.C" from Hero scanner
  const qs = new URLSearchParams(window.location.search);
  if (qs.get('open_cicpc') === '1') {
    openModal();
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (submitBtn) submitBtn.disabled = true;

    const payload = {
      scan_id: report.scan_id,
      channel_received: document.getElementById('cicpc-channel')?.value || 'whatsapp',
      impersonated_entity: document.getElementById('cicpc-entity')?.value || '',
      suspect_contact: document.getElementById('cicpc-suspect')?.value || '',
      incident_impact: document.getElementById('cicpc-impact')?.value || 'PREVENTIVE',
      citizen_statement: document.getElementById('cicpc-statement')?.value || '',
      reporter_contact: document.getElementById('cicpc-contact')?.value || '',
    };

    try {
      const res = await ApiClient.submitCicpcCase(payload);
      form.style.display = 'none';
      if (confirmBox) {
        confirmBox.style.display = 'block';
        confirmBox.textContent = '';

        const badge = document.createElement('span');
        badge.className = 'badge badge-safe';
        badge.textContent = `Expediente Registrado: ${res.data.case_number}`;

        const msg = document.createElement('p');
        msg.style.marginTop = '12px';
        msg.style.color = '#F1F5F9';
        msg.textContent = res.message;

        const hashInfo = document.createElement('p');
        hashInfo.className = 'mono';
        hashInfo.style.marginTop = '10px';
        hashInfo.style.fontSize = '0.78rem';
        hashInfo.style.color = '#00E1FF';
        hashInfo.style.wordBreak = 'break-all';
        hashInfo.textContent = `Sello SHA-256 transmitido: ${res.data.integrity_sha256}`;

        const doneBtn = document.createElement('button');
        doneBtn.type = 'button';
        doneBtn.className = 'btn btn-outline-cyan';
        doneBtn.style.marginTop = '16px';
        doneBtn.style.width = '100%';
        doneBtn.textContent = 'Entendido y Cerrar';
        doneBtn.onclick = closeModal;

        confirmBox.append(badge, msg, hashInfo, doneBtn);
      }

      if (openBtn) {
        openBtn.textContent = `Remitido (${res.data.case_number})`;
      }
      showToast(`Caso registrado bajo expediente ${res.data.case_number}`);
    } catch (err) {
      showToast(err.message || 'No se pudo remitir la notificación.', true);
    } finally {
      if (submitBtn) submitBtn.disabled = false;
    }
  });
}
