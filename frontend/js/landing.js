import {
  ApiClient,
  formatRelativeTime,
  initMobileNavbar,
  setPendingScanId,
  showToast,
  syncNavbarAuth,
} from './api-client.js';
import { ExportService } from './export-service.js';
import { createSvgIcon } from './icons.js';
import { initPwaSupport } from './pwa-install.js';

const XRAY_HOTSPOTS = {
  1: {
    title: 'Punto 01 — Dirección sin candado cifrado (http://)',
    text: 'El atacante montó la página sin cifrado HTTPS para levantarla rápido. Detector360 detecta que tu contraseña viajaría abierta como una postal sin sobre y te frena al instante.',
  },
  2: {
    title: 'Punto 02 — Envío secreto a servidor pirata (action="http://robo-datos.xyz")',
    text: 'Aunque ves el logotipo de tu banco, el botón de envío desvía tus datos hacia el dominio de un criminal externo. Detector360 lee el atributo oculto <form action> y bloquea el engaño.',
  },
  3: {
    title: 'Punto 03 — Espía silencioso de teclado (<script> keyup)',
    text: 'Un programa oculto graba cada letra y número que presionas incluso antes de hacer clic en Enviar. Detector360 inspecciona los scripts internos y te alerta antes de tocar el teclado.',
  },
};

let currentUser = null;
let latestHeroReport = null;

document.addEventListener('DOMContentLoaded', async () => {
  initMobileNavbar();
  currentUser = await syncNavbarAuth();

  initHeroWidescreenVideo();
  initFooterCicpcVideo();
  initHeroScanner();
  initXraySimulator();
  initScamCards();
  initPlanLeadModal();
  await loadLiveCommercialFeed();

  initPwaSupport((sharedUrl) => {
    const input = document.getElementById('hero-url-input');
    if (input) {
      input.value = sharedUrl;
      executeHeroScan(sharedUrl);
    }
  });
});

function initHeroWidescreenVideo() {
  const video = document.getElementById('hero-widescreen-video');
  const soundBtn = document.getElementById('hero-video-sound-btn');
  const soundLabel = document.getElementById('hero-video-sound-label');
  const playBtn = document.getElementById('hero-video-play-btn');
  const playLabel = document.getElementById('hero-video-play-label');
  const scanCta = document.getElementById('hero-cinema-scan-cta');

  if (video && soundBtn && soundLabel) {
    soundBtn.addEventListener('click', () => {
      video.muted = !video.muted;
      if (!video.muted && video.paused) {
        video.play().catch(() => {});
      }
      soundBtn.setAttribute('aria-pressed', String(!video.muted));
      soundLabel.textContent = video.muted ? 'Activar Audio' : 'Silenciar Audio';
    });
  }

  if (video && playBtn && playLabel) {
    playBtn.addEventListener('click', () => {
      if (video.paused) {
        video.play().catch(() => {});
        playBtn.setAttribute('aria-pressed', 'false');
        playLabel.textContent = 'Pausar';
      } else {
        video.pause();
        playBtn.setAttribute('aria-pressed', 'true');
        playLabel.textContent = 'Reproducir';
      }
    });
  }

  if (scanCta) {
    scanCta.addEventListener('click', () => {
      setTimeout(() => {
        const input = document.getElementById('hero-url-input');
        if (input) input.focus({ preventScroll: true });
      }, 420);
    });
  }
}

function initFooterCicpcVideo() {
  const video = document.getElementById('footer-cicpc-video');
  const soundBtn = document.getElementById('footer-video-sound-btn');
  const soundLabel = document.getElementById('footer-video-sound-label');
  const playBtn = document.getElementById('footer-video-play-btn');
  const playLabel = document.getElementById('footer-video-play-label');

  if (video && soundBtn && soundLabel) {
    soundBtn.addEventListener('click', () => {
      video.muted = !video.muted;
      if (!video.muted && video.paused) {
        video.play().catch(() => {});
      }
      soundBtn.setAttribute('aria-pressed', String(!video.muted));
      soundLabel.textContent = video.muted ? 'Activar Audio' : 'Silenciar';
    });
  }

  if (video && playBtn && playLabel) {
    playBtn.addEventListener('click', () => {
      if (video.paused) {
        video.play().catch(() => {});
        playBtn.setAttribute('aria-pressed', 'false');
        playLabel.textContent = 'Pausar';
      } else {
        video.pause();
        playBtn.setAttribute('aria-pressed', 'true');
        playLabel.textContent = 'Reproducir';
      }
    });
  }
}

function initHeroScanner() {
  const form = document.getElementById('hero-scan-form');
  const input = document.getElementById('hero-url-input');
  const pasteBtn = document.getElementById('hero-paste-btn');

  if (pasteBtn && input) {
    pasteBtn.addEventListener('click', async () => {
      try {
        const text = await navigator.clipboard.readText();
        if (text && text.trim()) {
          input.value = text.trim();
          input.focus();
          showToast('Enlace pegado. Pulsa "Analizar Gratis Ahora".');
        } else {
          showToast('Tu portapapeles está vacío. Copia primero el enlace sospechoso.', true);
        }
      } catch {
        input.focus();
        showToast('Mantén presionado el recuadro y elige "Pegar" para insertar el enlace.');
      }
    });
  }

  document.querySelectorAll('[data-demo-url]').forEach((chip) => {
    chip.addEventListener('click', () => {
      const demoUrl = chip.getAttribute('data-demo-url') || '';
      if (input && demoUrl) {
        input.value = demoUrl;
        executeHeroScan(demoUrl);
      }
    });
  });

  if (form && input) {
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      executeHeroScan(input.value);
    });
  }
}

async function executeHeroScan(rawUrl) {
  const errorBanner = document.getElementById('scanner-error-banner');
  const progressPanel = document.getElementById('scan-progress-panel');
  const progressBar = document.getElementById('scan-progress-bar');
  const submitBtn = document.getElementById('hero-scan-submit');
  const verdictCard = document.getElementById('instant-verdict-card');

  const step1 = document.getElementById('scan-step-1');
  const step2 = document.getElementById('scan-step-2');
  const step3 = document.getElementById('scan-step-3');

  if (errorBanner) errorBanner.classList.remove('visible');
  if (verdictCard) verdictCard.classList.remove('visible');

  const trimmed = (rawUrl || '').trim();
  if (!trimmed) {
    if (errorBanner) {
      errorBanner.textContent = 'Pega primero el enlace sospechoso que deseas revisar.';
      errorBanner.classList.add('visible');
    }
    return;
  }

  if (submitBtn) submitBtn.disabled = true;
  if (progressPanel) progressPanel.classList.add('active');

  setStepState(step1, 'active');
  setStepState(step2, '');
  setStepState(step3, '');
  if (progressBar) progressBar.style.transform = 'scaleX(0.32)';

  const t1 = setTimeout(() => {
    setStepState(step1, 'done');
    setStepState(step2, 'active');
    if (progressBar) progressBar.style.transform = 'scaleX(0.68)';
  }, 220);

  const t2 = setTimeout(() => {
    setStepState(step2, 'done');
    setStepState(step3, 'active');
    if (progressBar) progressBar.style.transform = 'scaleX(0.92)';
  }, 440);

  try {
    const apiPromise = ApiClient.runScan({
      url: trimmed,
      force_refresh: false,
      save_snapshot: true,
    });

    const [res] = await Promise.all([
      apiPromise,
      new Promise((resolve) => setTimeout(resolve, 520)),
    ]);

    clearTimeout(t1);
    clearTimeout(t2);
    setStepState(step1, 'done');
    setStepState(step2, 'done');
    setStepState(step3, 'done');
    if (progressBar) progressBar.style.transform = 'scaleX(1)';

    const report = res.data;
    latestHeroReport = report;
    if (!currentUser) {
      setPendingScanId(report.scan_id);
    }

    setTimeout(() => {
      if (progressPanel) progressPanel.classList.remove('active');
      renderInstantVerdict(report);
      loadLiveCommercialFeed();
    }, 180);
  } catch (err) {
    clearTimeout(t1);
    clearTimeout(t2);
    if (progressPanel) progressPanel.classList.remove('active');
    if (errorBanner) {
      errorBanner.textContent =
        err.message ||
        'Revisa que el enlace esté bien escrito y comience por http:// o https://';
      errorBanner.classList.add('visible');
    }
  } finally {
    if (submitBtn) submitBtn.disabled = false;
  }
}

function setStepState(el, state) {
  if (!el) return;
  el.classList.remove('active', 'done');
  if (state) el.classList.add(state);
}

function renderInstantVerdict(report) {
  const card = document.getElementById('instant-verdict-card');
  if (!card) return;

  card.className = `instant-verdict-card visible level-${report.risk_level}`;
  card.textContent = '';

  const header = document.createElement('div');
  header.className = 'instant-verdict-header';

  const titleWrap = document.createElement('div');
  const badge = document.createElement('span');
  badge.className =
    report.risk_level === 'CRITICAL'
      ? 'badge badge-critical'
      : report.risk_level === 'WARNING'
      ? 'badge badge-warning'
      : 'badge badge-safe';

  const led = document.createElement('span');
  led.className =
    report.risk_level === 'CRITICAL'
      ? 'status-led critical'
      : report.risk_level === 'WARNING'
      ? 'status-led warning'
      : 'status-led safe';

  const badgeLabel = document.createElement('span');
  badgeLabel.textContent =
    report.risk_level === 'CRITICAL'
      ? 'Peligro Crítico Detectado'
      : report.risk_level === 'WARNING'
      ? 'Precaución Recomendada'
      : 'Sitio Seguro y Cifrado';

  badge.append(led, badgeLabel);

  const h3 = document.createElement('h3');
  h3.style.marginTop = '10px';
  h3.textContent = report.citizen_verdict?.title || '';

  const summary = document.createElement('p');
  summary.style.marginTop = '6px';
  summary.style.color = '#E2E8F0';
  summary.textContent = report.citizen_verdict?.summary || '';

  titleWrap.append(badge, h3, summary);

  const scorePill = document.createElement('div');
  scorePill.className = 'instant-score-pill';
  scorePill.textContent = `Riesgo ${report.risk_score}/100`;

  header.append(titleWrap, scorePill);
  card.appendChild(header);

  const ul = document.createElement('ul');
  ul.className = 'instant-reasons-list';

  if (report.findings && report.findings.length > 0) {
    report.findings.slice(0, 3).forEach((f) => {
      const li = document.createElement('li');
      li.textContent = f.citizen_explanation;
      ul.appendChild(li);
    });
  } else if (report.citizen_verdict?.action_steps) {
    report.citizen_verdict.action_steps.forEach((step) => {
      const li = document.createElement('li');
      li.textContent = step;
      ul.appendChild(li);
    });
  }
  card.appendChild(ul);

  const actionsBar = document.createElement('div');
  actionsBar.className = 'instant-actions-bar';

  const fullReportBtn = document.createElement('a');
  fullReportBtn.href = `/scan/${encodeURIComponent(report.scan_id)}`;
  fullReportBtn.className = 'btn btn-primary btn-sm';
  const fullTxt = document.createElement('span');
  fullTxt.textContent = 'Ver Rayos X del Código Completo';
  fullReportBtn.append(createSvgIcon('scanEye', 16), fullTxt);

  const shareBtn = document.createElement('button');
  shareBtn.type = 'button';
  shareBtn.className = 'btn btn-ghost btn-sm';
  const shareTxt = document.createElement('span');
  shareTxt.textContent = 'Compartir Alerta';
  shareBtn.append(createSvgIcon('share2', 15), shareTxt);
  shareBtn.addEventListener('click', () => {
    if (latestHeroReport) ExportService.copyAlertSummary(latestHeroReport);
  });

  const downloadBtn = document.createElement('button');
  downloadBtn.type = 'button';
  downloadBtn.className = 'btn btn-ghost btn-sm';
  const dlTxt = document.createElement('span');
  dlTxt.textContent = 'Descargar Evidencia';
  downloadBtn.append(createSvgIcon('download', 15), dlTxt);
  downloadBtn.addEventListener('click', () => {
    if (latestHeroReport) ExportService.downloadJsonEvidence(latestHeroReport);
  });

  const cicpcNotifyLink = document.createElement('a');
  cicpcNotifyLink.href = `/scan/${encodeURIComponent(report.scan_id)}?open_cicpc=1`;
  cicpcNotifyLink.className = 'btn btn-outline-cyan btn-sm';
  const cicpcTxt = document.createElement('span');
  cicpcTxt.textContent = 'Notificar Caso al C.I.C.P.C';
  cicpcNotifyLink.append(createSvgIcon('shieldAlert', 15), cicpcTxt);

  actionsBar.append(fullReportBtn, cicpcNotifyLink, shareBtn, downloadBtn);

  if (!currentUser) {
    const saveHistoryLink = document.createElement('a');
    saveHistoryLink.href = `/register?pending_scan_id=${encodeURIComponent(report.scan_id)}`;
    saveHistoryLink.className = 'btn btn-outline-cyan btn-sm';
    const saveTxt = document.createElement('span');
    saveTxt.textContent = 'Crear cuenta gratis para guardar historial';
    saveHistoryLink.append(createSvgIcon('userPlus', 15), saveTxt);
    actionsBar.appendChild(saveHistoryLink);
  }

  card.appendChild(actionsBar);
}

function initXraySimulator() {
  const toggleBtn = document.getElementById('xray-toggle-btn');
  const toggleLabel = document.getElementById('xray-toggle-label');
  const browserWindow = document.getElementById('xray-browser-window');
  const addressProtocol = document.getElementById('xray-address-protocol');
  const detailTitle = document.getElementById('hotspot-detail-title');
  const detailText = document.getElementById('hotspot-detail-text');
  const tryRealBtn = document.getElementById('xray-try-real-btn');

  if (toggleBtn && browserWindow) {
    toggleBtn.addEventListener('click', () => {
      const isNowActive = !browserWindow.classList.contains('xray-active');
      browserWindow.classList.toggle('xray-active', isNowActive);
      toggleBtn.setAttribute('aria-pressed', String(isNowActive));

      if (toggleLabel) {
        toggleLabel.textContent = isNowActive
          ? 'Visión Forense Detector360: ACTIVADA'
          : 'Activar Visión Forense Detector360';
      }
      if (addressProtocol) {
        addressProtocol.textContent = isNowActive
          ? 'SIN CANDADO TLS (http://)'
          : 'Apariencia normal';
      }
    });
  }

  document.querySelectorAll('[data-hotspot]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const id = btn.getAttribute('data-hotspot');
      const info = XRAY_HOTSPOTS[id];
      if (!info) return;

      document.querySelectorAll('[data-hotspot]').forEach((b) => b.classList.remove('selected'));
      btn.classList.add('selected');

      if (detailTitle) detailTitle.textContent = info.title;
      if (detailText) detailText.textContent = info.text;
    });
  });

  if (tryRealBtn) {
    tryRealBtn.addEventListener('click', () => {
      const heroInput = document.getElementById('hero-url-input');
      const heroSection = document.getElementById('hero-scanner');
      if (heroSection) {
        heroSection.scrollIntoView({ behavior: 'smooth' });
      }
      setTimeout(() => {
        heroInput?.focus();
      }, 450);
    });
  }
}

function initScamCards() {
  document.querySelectorAll('.scam-card').forEach((card) => {
    card.addEventListener('click', () => {
      card.classList.toggle('expanded');
    });
    card.addEventListener('keydown', (ev) => {
      if (ev.key === 'Enter' || ev.key === ' ') {
        ev.preventDefault();
        card.classList.toggle('expanded');
      }
    });
  });
}

async function loadLiveCommercialFeed() {
  const totalEl = document.getElementById('metric-total-scans');
  const blockedEl = document.getElementById('metric-threats-blocked');
  const speedEl = document.getElementById('metric-avg-speed');
  const wallGrid = document.getElementById('threat-wall-grid');

  try {
    const res = await ApiClient.getLandingFeed();
    const metrics = res?.data?.metrics;
    const alerts = res?.data?.recent_alerts || [];

    if (metrics) {
      if (totalEl) {
        totalEl.textContent = `${Number(metrics.total_scans_executed).toLocaleString('es-ES')}+`;
      }
      if (blockedEl) {
        blockedEl.textContent = `${Number(metrics.critical_threats_blocked).toLocaleString('es-ES')}`;
      }
      if (speedEl) {
        const secs = (Number(metrics.avg_scan_duration_ms || 1380) / 1000).toFixed(1);
        speedEl.textContent = `${secs}s`;
      }
    }

    if (wallGrid && alerts.length > 0) {
      wallGrid.textContent = '';
      alerts.slice(0, 3).forEach((item) => {
        const card = document.createElement('article');
        card.className = 'threat-card';

        const topRow = document.createElement('div');
        topRow.className = 'threat-meta-row';

        const critBadge = document.createElement('span');
        critBadge.className = 'badge badge-critical';
        const critLed = document.createElement('span');
        critLed.className = 'status-led critical';
        const critTxt = document.createElement('span');
        critTxt.textContent = 'Crítico';
        critBadge.append(critLed, critTxt);

        const timeSpan = document.createElement('span');
        timeSpan.textContent = formatRelativeTime(item.detected_at);
        topRow.append(critBadge, timeSpan);

        const domainCode = document.createElement('div');
        domainCode.className = 'threat-domain-code';
        domainCode.textContent = item.masked_domain;

        const categoryP = document.createElement('p');
        categoryP.style.fontWeight = '600';
        categoryP.textContent = item.threat_category;

        const meterTrack = document.createElement('div');
        meterTrack.className = 'threat-meter-track';
        const meterFill = document.createElement('div');
        meterFill.className = 'threat-meter-fill';
        meterFill.style.width = `${Math.min(100, Math.max(20, Number(item.risk_score)))}%`;
        meterTrack.appendChild(meterFill);

        const bottomRow = document.createElement('div');
        bottomRow.className = 'threat-meta-row';

        const scoreSpan = document.createElement('span');
        scoreSpan.className = 'mono tabular-nums';
        scoreSpan.style.color = '#F87171';
        scoreSpan.textContent = `Riesgo ${item.risk_score}/100`;

        if (item.scan_id) {
          const viewLink = document.createElement('a');
          viewLink.href = `/scan/${encodeURIComponent(item.scan_id)}`;
          viewLink.style.display = 'inline-flex';
          viewLink.style.alignItems = 'center';
          viewLink.style.gap = '4px';
          const linkTxt = document.createElement('span');
          linkTxt.textContent = 'Ver evidencia';
          viewLink.append(linkTxt, createSvgIcon('arrowRight', 14));
          bottomRow.append(scoreSpan, viewLink);
        } else {
          bottomRow.appendChild(scoreSpan);
        }

        card.append(topRow, domainCode, categoryP, meterTrack, bottomRow);
        wallGrid.appendChild(card);
      });
    }
  } catch {
    // Keep clean static fallback if offline
  }
}

function initPlanLeadModal() {
  const modal = document.getElementById('plan-lead-modal');
  const closeBtn = document.getElementById('plan-modal-close');
  const form = document.getElementById('plan-lead-form');
  const planSelect = document.getElementById('lead-plan-select');
  const phoneLabel = document.getElementById('lead-phone-domain-label');
  const phoneInput = document.getElementById('lead-phone-domain');
  const successBox = document.getElementById('plan-lead-success');

  if (!modal || !form) return;

  const updateFieldHint = (planVal) => {
    if (!phoneLabel || !phoneInput) return;
    if (planVal === 'verified_merchant') {
      phoneLabel.textContent = 'Dominio web de tu comercio a proteger';
      phoneInput.placeholder = 'Ej: mitiendaoficial.com';
    } else {
      phoneLabel.textContent = 'Teléfono principal de contacto (WhatsApp)';
      phoneInput.placeholder = 'Ej: +58 412 555 0199';
    }
  };

  document.querySelectorAll('[data-open-plan-modal]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const plan = btn.getAttribute('data-open-plan-modal') || 'family_shield';
      if (planSelect) planSelect.value = plan;
      updateFieldHint(plan);
      if (successBox) successBox.style.display = 'none';
      form.style.display = 'block';
      modal.classList.add('active');
    });
  });

  if (planSelect) {
    planSelect.addEventListener('change', () => updateFieldHint(planSelect.value));
  }

  if (closeBtn) {
    closeBtn.addEventListener('click', () => modal.classList.remove('active'));
  }

  modal.addEventListener('click', (ev) => {
    if (ev.target === modal) modal.classList.remove('active');
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const submitBtn = document.getElementById('lead-submit-btn');
    if (submitBtn) submitBtn.disabled = true;

    const payload = {
      plan_selected: planSelect ? planSelect.value : 'family_shield',
      full_name: document.getElementById('lead-full-name')?.value || '',
      email: document.getElementById('lead-email')?.value || '',
      phone_or_domain: phoneInput?.value || '',
      notes: document.getElementById('lead-notes')?.value || '',
    };

    try {
      const res = await ApiClient.createLead(payload);
      form.reset();
      form.style.display = 'none';
      if (successBox) {
        successBox.textContent = '';
        const title = document.createElement('h3');
        title.style.color = '#34D399';
        title.style.display = 'flex';
        title.style.alignItems = 'center';
        title.style.gap = '8px';
        const titleTxt = document.createElement('span');
        titleTxt.textContent = 'Solicitud Prioritaria Confirmada';
        title.append(createSvgIcon('checkCircle', 20), titleTxt);

        const msg = document.createElement('p');
        msg.style.marginTop = '10px';
        msg.textContent = res.message;

        const idTag = document.createElement('p');
        idTag.className = 'mono';
        idTag.style.marginTop = '10px';
        idTag.style.fontSize = '0.82rem';
        idTag.style.color = '#94A3B8';
        idTag.textContent = `Código de solicitud: ${res.data.lead_id}`;

        successBox.append(title, msg, idTag);
        successBox.style.display = 'block';
      }
      showToast('Solicitud de activación registrada con éxito.');
    } catch (err) {
      showToast(err.message || 'Verifica los datos ingresados.', true);
    } finally {
      if (submitBtn) submitBtn.disabled = false;
    }
  });
}
