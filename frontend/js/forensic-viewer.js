import { ExportService } from './export-service.js';

/**
 * Helper to create DOM elements safely using strictly textContent / createTextNode
 * (Zero innerHTML with untrusted external strings to guarantee 100% XSS immunity).
 */
function el(tag, className = '', text = null) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== null && text !== undefined) {
    node.textContent = String(text);
  }
  return node;
}

function severityLabel(sev) {
  switch (sev) {
    case 'CRITICAL':
      return 'CRÍTICA';
    case 'HIGH':
      return 'ALTA';
    case 'MEDIUM':
      return 'MEDIA';
    case 'LOW':
    default:
      return 'BAJA / INFO';
  }
}

function severityBadgeClass(sev) {
  if (sev === 'CRITICAL' || sev === 'HIGH') return 'badge badge-critical';
  if (sev === 'MEDIUM') return 'badge badge-warning';
  return 'badge badge-safe';
}

export const ForensicViewer = {
  /**
   * Renders the 4 forensic blocks into `containerElement` safely without innerHTML.
   */
  renderReport(containerElement, reportData) {
    containerElement.replaceChildren();

    // Printable Official Header (visible only in PDF/Print mode)
    const printHeader = el('div', 'print-only-header');
    const printTitle = el('h2', '', 'Detector360 — Acta Ciudadana de Evidencia Forense Web');
    const printMeta = el(
      'p',
      'mono',
      `ID Auditoría: ${reportData.scan_id} | Fecha UTC: ${reportData.scanned_at} | Dominio: ${reportData.target_domain}`
    );
    printHeader.append(printTitle, printMeta);
    containerElement.appendChild(printHeader);

    if (reportData.is_demo_simulation) {
      const demoNotice = el(
        'div',
        'feedback-alert',
        'Modo Demostración Forense Local: Este análisis proviene del corpus de prueba integrado para inspección de interfaz y verificación SHA-256.'
      );
      demoNotice.style.background = '#E0F2FE';
      demoNotice.style.color = '#075985';
      demoNotice.style.border = '1px solid #7DD3FC';
      containerElement.appendChild(demoNotice);
    }

    // =========================================================================
    // BLOCK 1: Citizen Verdict Banner (Semáforo 0 - 100)
    // =========================================================================
    const verdictClass =
      reportData.risk_level === 'CRITICAL'
        ? 'verdict-critical'
        : reportData.risk_level === 'WARNING'
          ? 'verdict-warning'
          : 'verdict-safe';

    const banner = el('section', `verdict-banner ${verdictClass}`);
    banner.setAttribute('aria-live', 'polite');

    const circle = el('div', 'score-circle');
    circle.append(
      el('span', 'score-number', reportData.risk_score),
      el('span', 'score-max', '/ 100')
    );

    const verdictBody = el('div', '');
    const levelText =
      reportData.risk_level === 'CRITICAL'
        ? 'RIESGO CRÍTICO'
        : reportData.risk_level === 'WARNING'
          ? 'PRECAUCIÓN'
          : 'BAJO RIESGO / SEGURO';

    const topBadge = el('span', 'badge', levelText);
    topBadge.style.background = 'rgba(255,255,255,0.75)';
    topBadge.style.marginBottom = '8px';

    const titleH2 = el('h2', '', reportData.citizen_verdict?.title || '');
    const summaryP = el('p', '', reportData.citizen_verdict?.summary || '');
    summaryP.style.marginBottom = '8px';

    const urlMeta = el(
      'div',
      'mono',
      `URL auditada: ${reportData.final_url || reportData.target_url} (${reportData.duration_ms} ms)`
    );

    verdictBody.append(topBadge, titleH2, summaryP, urlMeta);
    banner.append(circle, verdictBody);
    containerElement.appendChild(banner);

    // =========================================================================
    // BLOCK 2: Transport & Network Security Summary
    // =========================================================================
    const transportCard = el('section', 'card');
    transportCard.appendChild(el('h3', '', '1. Auditoría de Capa de Transporte y Red'));
    transportCard.appendChild(
      el('p', 'text-muted', 'Estado del cifrado en tránsito, saltos de redirección y cabeceras HTTP.')
    );

    const tAudit = reportData.transport_audit || {};
    const secHeaders = tAudit.security_headers || {};
    const grid = el('div', 'transport-grid');

    // Tile 1: Protocol
    const tileProto = el('div', 'transport-tile');
    tileProto.append(
      el('div', 'transport-tile-label', 'Protocolo'),
      el(
        'div',
        'transport-tile-val',
        tAudit.is_https ? 'HTTPS (Cifrado)' : 'HTTP (Sin Cifrar - Texto Plano)'
      )
    );
    tileProto.style.borderLeft = `4px solid ${tAudit.is_https ? '#16A34A' : '#DC2626'}`;

    // Tile 2: TLS Status
    const tileTls = el('div', 'transport-tile');
    tileTls.append(
      el('div', 'transport-tile-label', 'Estado TLS / HTTP'),
      el(
        'div',
        'transport-tile-val',
        tAudit.is_https
          ? `TLS Activo (HTTP ${tAudit.http_status_code || 200})`
          : `Ausente (HTTP ${tAudit.http_status_code || 200})`
      )
    );

    // Tile 3: Redirects
    const tileRedir = el('div', 'transport-tile');
    const hops = tAudit.redirect_count || 0;
    tileRedir.append(
      el('div', 'transport-tile-label', 'Redirecciones'),
      el('div', 'transport-tile-val', hops === 0 ? '0 saltos directos' : `${hops} salto(s) detectado(s)`)
    );

    // Tile 4: Security Headers
    const tileHeaders = el('div', 'transport-tile');
    const presentCount = [
      secHeaders.strict_transport_security,
      secHeaders.content_security_policy,
      secHeaders.x_frame_options
    ].filter(Boolean).length;
    tileHeaders.append(
      el('div', 'transport-tile-label', 'Cabeceras HSTS / CSP / XFO'),
      el('div', 'transport-tile-val', `${presentCount} de 3 activas`)
    );

    grid.append(tileProto, tileTls, tileRedir, tileHeaders);
    transportCard.appendChild(grid);
    containerElement.appendChild(transportCard);

    // =========================================================================
    // BLOCK 3: Detected Infractions List
    // =========================================================================
    const findingsCard = el('section', 'card');
    const findingsList = Array.isArray(reportData.findings) ? reportData.findings : [];

    findingsCard.appendChild(
      el('h3', '', `2. Infracciones Detectadas (${findingsList.length})`)
    );

    if (findingsList.length === 0) {
      const cleanBox = el(
        'div',
        'feedback-alert feedback-success',
        'No se detectaron formularios inseguros, envíos cross-domain ni scripts de exfiltración u ofuscación en el código analizado.'
      );
      cleanBox.style.marginTop = '12px';
      cleanBox.style.marginBottom = '0';
      findingsCard.appendChild(cleanBox);
    } else {
      findingsCard.appendChild(
        el(
          'p',
          'text-muted',
          'Cada hallazgo incluye traducción ciudadana y ubicación exacta (línea y selector DOM) en el documento fuente.'
        )
      );

      const stack = el('div', 'findings-stack');
      for (const f of findingsList) {
        const fCard = el('article', `finding-card sev-${f.severity}`);

        const metaRow = el('div', 'finding-meta-row');
        metaRow.append(
          el('span', severityBadgeClass(f.severity), severityLabel(f.severity)),
          el('span', 'badge badge-tech', f.rule_code),
          el('span', 'badge badge-tech', `Línea ${f.line_number}:${f.column_number || 1}`),
          el('span', 'badge badge-tech', f.dom_selector)
        );

        const citizenP = el('p', '', f.citizen_explanation);
        citizenP.style.fontWeight = '600';
        citizenP.style.marginBottom = '6px';

        const techP = el('p', 'text-muted', `Diagnóstico técnico: ${f.technical_detail}`);
        techP.style.marginBottom = '8px';

        // Strictly textContent snippet -> XSS impossible
        const snippetPre = el('pre', 'finding-snippet');
        snippetPre.appendChild(document.createTextNode(f.code_snippet || ''));

        fCard.append(metaRow, citizenP, techP, snippetPre);
        stack.appendChild(fCard);
      }
      findingsCard.appendChild(stack);
    }

    containerElement.appendChild(findingsCard);

    // =========================================================================
    // BLOCK 4: Obsidian Terminal Source Code Viewer (#0B1120)
    // =========================================================================
    const sourceSection = el('section', 'code-viewer-container');
    const toolbar = el('div', 'code-viewer-toolbar');
    toolbar.appendChild(
      el('span', 'code-viewer-title', '3. Visor Forense de Código Fuente Sanitizado (Solo Lectura)')
    );

    const filterLabel = el('label', 'checkbox-row no-print');
    filterLabel.style.margin = '0';
    filterLabel.style.color = '#E2E8F0';
    filterLabel.style.fontSize = '13px';

    const filterCheckbox = document.createElement('input');
    filterCheckbox.type = 'checkbox';
    filterCheckbox.id = 'toggle-only-findings';
    filterLabel.append(
      filterCheckbox,
      document.createTextNode('Mostrar solo líneas con infracciones')
    );
    toolbar.appendChild(filterLabel);

    const linesScroll = el('div', 'code-lines-scroll');
    const previewLines = Array.isArray(reportData.source_preview) ? reportData.source_preview : [];

    const renderCodeLines = (onlyInfractions) => {
      linesScroll.replaceChildren();
      const filtered = onlyInfractions
        ? previewLines.filter((item) => item.has_finding)
        : previewLines;

      if (filtered.length === 0) {
        const emptyRow = el(
          'div',
          'code-line-row',
          onlyInfractions
            ? 'No hay líneas marcadas con infracciones directas en el código HTML/JS.'
            : 'Sin vista previa de código fuente disponible.'
        );
        linesScroll.appendChild(emptyRow);
        return;
      }

      for (const row of filtered) {
        const rowDiv = el(
          'div',
          row.has_finding ? 'code-line-row is-infringing' : 'code-line-row'
        );

        const numSpan = el('span', 'code-line-num', `L${row.line}`);
        const codeSpan = el('span', 'code-line-text');
        // Strictly createTextNode so <script>alert(1)</script> renders as harmless text
        codeSpan.appendChild(document.createTextNode(row.content || ' '));

        rowDiv.append(numSpan, codeSpan);
        linesScroll.appendChild(rowDiv);
      }
    };

    filterCheckbox.addEventListener('change', () => {
      renderCodeLines(filterCheckbox.checked);
    });

    renderCodeLines(false);
    sourceSection.append(toolbar, linesScroll);
    containerElement.appendChild(sourceSection);

    // =========================================================================
    // BLOCK 5: Cryptographic Integrity Verification Box (SHA-256)
    // =========================================================================
    const integrityCard = el('section', 'integrity-box');
    const intHeader = el('div', 'section-header-row');
    intHeader.style.marginBottom = '0';
    intHeader.appendChild(el('strong', '', '4. Firma de Integridad Forense (SHA-256)'));

    const verifyBtn = el('button', 'btn btn-secondary btn-sm no-print', 'Verificar Integridad SHA-256');
    verifyBtn.type = 'button';
    intHeader.appendChild(verifyBtn);

    const hashBox = el('div', 'hash-display', reportData.integrity_sha256 || 'N/A');
    const verifyStatus = el('div', 'text-muted', '');

    verifyBtn.addEventListener('click', async () => {
      verifyBtn.disabled = true;
      const check = await ExportService.verifyReportIntegrity(reportData);
      verifyBtn.disabled = false;

      if (check.valid) {
        verifyStatus.className = 'feedback-alert feedback-success';
        verifyStatus.style.marginBottom = '0';
        verifyStatus.textContent = `Integridad verificada matemáticamente: el hash recalculado sobre evidence_payload coincide al 100% (${check.computedHash}).`;
      } else {
        verifyStatus.className = 'feedback-alert feedback-error';
        verifyStatus.style.marginBottom = '0';
        verifyStatus.textContent =
          'Advertencia: el hash recalculado no coincide con la firma registrada.';
      }
    });

    integrityCard.append(intHeader, hashBox, verifyStatus);
    containerElement.appendChild(integrityCard);
  }
};
