import { ApiClient, showToast } from './api-client.js';

const STORAGE_KEYS = {
  SENIOR_MODE: 'd360_senior_mode',
  AUTO_VOICE: 'd360_auto_voice',
  SENIOR_NAME: 'd360_senior_name',
  GUARDIAN_NAME: 'd360_guardian_name',
  GUARDIAN_PHONE: 'd360_guardian_phone',
  GUARDIAN_AUTO_CRITICAL: 'd360_guardian_auto_critical',
  LAST_GUARDIAN_TOKEN: 'd360_last_guardian_token',
};

const EMERGENCY_PHONES_BY_SLUG = {
  banesco: { name: 'Banesco', phone: '0500-2263726' },
  'banco-de-venezuela': { name: 'Banco de Venezuela (BDV)', phone: '0500-6425283' },
  mercantil: { name: 'Mercantil Banco', phone: '0212-5032522' },
  provincial: { name: 'BBVA Provincial', phone: '0500-5087432' },
  bnc: { name: 'Banco Nacional de Crédito (BNC)', phone: '0500-2625000' },
  bancamiga: { name: 'Bancamiga', phone: '0500-8822622' },
};

let externalUrlScanHandler = null;
let antiPanicInterval = null;
let guardianPollInterval = null;
let activeQrStream = null;
let qrScanLoopActive = false;
let simulatorQuestions = [];
let simulatorIndex = 0;
let simulatorScore = 0;
let currentDirectoryCategory = 'ALL';

export function isSeniorModeActive() {
  try {
    return localStorage.getItem(STORAGE_KEYS.SENIOR_MODE) === '1';
  } catch {
    return false;
  }
}

export function isAutoVoiceEnabled() {
  try {
    const stored = localStorage.getItem(STORAGE_KEYS.AUTO_VOICE);
    if (stored === '1') return true;
    if (stored === '0') return false;
    return isSeniorModeActive();
  } catch {
    return isSeniorModeActive();
  }
}

export function stopSpeech() {
  if (typeof window !== 'undefined' && 'speechSynthesis' in window) {
    try {
      window.speechSynthesis.cancel();
    } catch {
      // Ignorar restricción del navegador
    }
  }
}

export function speakTextAloud(text) {
  if (!text || typeof window === 'undefined' || !('speechSynthesis' in window)) {
    showToast('Tu navegador actual no dispone de lectura por voz integrada.', true);
    return false;
  }

  try {
    window.speechSynthesis.cancel();
    const utterance = new SpeechSynthesisUtterance(text);
    utterance.lang = 'es-ES';
    utterance.rate = 0.88;
    utterance.pitch = 1.0;

    const voices = window.speechSynthesis.getVoices() || [];
    const esVoice =
      voices.find((v) => /^es[-_](VE|CO|MX|419)/i.test(v.lang)) ||
      voices.find((v) => /^es/i.test(v.lang));
    if (esVoice) {
      utterance.voice = esVoice;
      utterance.lang = esVoice.lang;
    }

    window.speechSynthesis.speak(utterance);
    return true;
  } catch {
    return false;
  }
}

export function buildVerdictSpeechScript(report) {
  if (!report) return '';
  if (report.spoken_script) return report.spoken_script;

  const title = report.citizen_verdict?.title || '';
  const summary = report.citizen_verdict?.summary || '';
  if (report.risk_level === 'CRITICAL') {
    return `Atención. Semáforo en Rojo. Peligro detectado. No abras este enlace ni escribas tus claves. ${title}. ${summary}`;
  }
  if (report.risk_level === 'WARNING') {
    return `Atención. Semáforo en Amarillo. Ten precaución antes de entrar. ${title}. ${summary}`;
  }
  return `Semáforo en Verde. Sitio seguro y cifrado. ${title}. ${summary}`;
}

export function renderSeniorSemaphore(report, targetContainerId = 'senior-semaphore-banner') {
  const box = document.getElementById(targetContainerId);
  if (!box || !report) return;

  const showSemaphore = isSeniorModeActive() || box.dataset.alwaysShow === '1';
  if (!showSemaphore) {
    box.className = 'senior-semaphore-banner';
    box.textContent = '';
    return;
  }

  box.className = `senior-semaphore-banner visible sem-${report.risk_level}`;
  box.textContent = '';

  const lightsRow = document.createElement('div');
  lightsRow.className = 'semaphore-lights-row';
  lightsRow.setAttribute('aria-hidden', 'true');

  const redBulb = document.createElement('span');
  redBulb.className = `semaphore-bulb red${report.risk_level === 'CRITICAL' ? ' lit' : ''}`;
  const yellowBulb = document.createElement('span');
  yellowBulb.className = `semaphore-bulb yellow${report.risk_level === 'WARNING' ? ' lit' : ''}`;
  const greenBulb = document.createElement('span');
  greenBulb.className = `semaphore-bulb green${report.risk_level === 'SAFE' ? ' lit' : ''}`;

  lightsRow.append(redBulb, yellowBulb, greenBulb);

  const heading = document.createElement('h3');
  heading.style.fontSize = '1.5rem';
  heading.style.margin = '0 0 8px';
  heading.style.color = '#FFFFFF';
  heading.textContent =
    report.risk_level === 'CRITICAL'
      ? 'SEMÁFORO ROJO: NO ENTRES NI ENTREGUES TUS CLAVES'
      : report.risk_level === 'WARNING'
      ? 'SEMÁFORO AMARILLO: DETENTE Y CONSULTA A UN FAMILIAR'
      : 'SEMÁFORO VERDE: ENLACE OFICIAL Y SEGURO';

  const desc = document.createElement('p');
  desc.style.fontSize = '1.08rem';
  desc.style.margin = '0';
  desc.style.color = '#F8FAFC';
  desc.textContent = report.citizen_verdict?.summary || '';

  box.append(lightsRow, heading, desc);
}

/**
 * Crea la barra de botones de asistencia para personas mayores dentro de cualquier tarjeta de veredicto
 */
export function buildSeniorAssistActionsBar(report) {
  const bar = document.createElement('div');
  bar.className = 'senior-verdict-assist-bar';

  const speakBtn = document.createElement('button');
  speakBtn.type = 'button';
  speakBtn.className = 'btn btn-sm btn-voice-speak';
  speakBtn.textContent = 'Escuchar Resultado por Voz';
  speakBtn.addEventListener('click', () => {
    speakTextAloud(buildVerdictSpeechScript(report));
  });

  const stopVoiceBtn = document.createElement('button');
  stopVoiceBtn.type = 'button';
  stopVoiceBtn.className = 'btn btn-ghost btn-sm';
  stopVoiceBtn.textContent = 'Detener Voz';
  stopVoiceBtn.addEventListener('click', () => stopSpeech());

  const askGuardianBtn = document.createElement('button');
  askGuardianBtn.type = 'button';
  askGuardianBtn.className = 'btn btn-sm btn-guardian-ask';
  askGuardianBtn.textContent = 'Preguntar a mi Hijo / Familiar en 1 Toque';
  askGuardianBtn.addEventListener('click', () => {
    askGuardianOneTap({
      scan_id: report.scan_id,
      target_url: report.target_url || report.primary_url || '',
      message_excerpt: report.citizen_verdict?.title || '',
      risk_score: report.risk_score,
      risk_level: report.risk_level,
      alert_mode: 'ASK_GUARDIAN',
    });
  });

  bar.append(speakBtn, stopVoiceBtn, askGuardianBtn);

  if (report.risk_level !== 'SAFE') {
    const emergencyBtn = document.createElement('button');
    emergencyBtn.type = 'button';
    emergencyBtn.className = 'btn btn-sm btn-emergency-inline';
    emergencyBtn.textContent = '¿Ya diste tu clave o hiciste un pago? Ayuda Urgente';
    emergencyBtn.addEventListener('click', () => openSeniorEmergencyModal(report.scan_id));
    bar.appendChild(emergencyBtn);
  }

  return bar;
}

/**
 * Ejecuta las reacciones automáticas tras un escaneo o análisis:
 * - Semáforo gigante si Modo Adulto Mayor está activo
 * - Lectura por voz automática si está habilitada
 * - Pausa Anti-Pánico de 15 segundos ante riesgo crítico / urgencia
 * - Alerta Automática al Familiar ("Ángel Guardián") ante riesgo CRITICAL
 */
export async function handlePostVerdictSeniorProtections(report) {
  if (!report) return;

  renderSeniorSemaphore(report);

  if (isAutoVoiceEnabled()) {
    speakTextAloud(buildVerdictSpeechScript(report));
  }

  if (report.risk_level === 'CRITICAL' || report.requires_anti_panic_pause) {
    triggerAntiPanicPause();
  }

  if (report.risk_level === 'CRITICAL') {
    await triggerGuardianAutoAlertIfConfigured(report);
  }
}

export function triggerAntiPanicPause() {
  const modal = document.getElementById('anti-panic-modal');
  const counterEl = document.getElementById('anti-panic-countdown');
  if (!modal || !counterEl) return;

  if (antiPanicInterval) {
    clearInterval(antiPanicInterval);
    antiPanicInterval = null;
  }

  let remaining = 15;
  counterEl.textContent = '15s';
  modal.classList.add('open');

  antiPanicInterval = setInterval(() => {
    remaining -= 1;
    if (remaining <= 0) {
      clearInterval(antiPanicInterval);
      antiPanicInterval = null;
      counterEl.textContent = 'Listo';
    } else {
      counterEl.textContent = `${remaining}s`;
    }
  }, 1000);
}

function closeAntiPanicModal() {
  const modal = document.getElementById('anti-panic-modal');
  if (antiPanicInterval) {
    clearInterval(antiPanicInterval);
    antiPanicInterval = null;
  }
  if (modal) modal.classList.remove('open');
}

function getGuardianConfig() {
  try {
    return {
      seniorName: localStorage.getItem(STORAGE_KEYS.SENIOR_NAME) || 'Mamá / Papá',
      guardianName: localStorage.getItem(STORAGE_KEYS.GUARDIAN_NAME) || '',
      guardianPhone: localStorage.getItem(STORAGE_KEYS.GUARDIAN_PHONE) || '',
      autoCritical: localStorage.getItem(STORAGE_KEYS.GUARDIAN_AUTO_CRITICAL) !== '0',
    };
  } catch {
    return {
      seniorName: 'Mamá / Papá',
      guardianName: '',
      guardianPhone: '',
      autoCritical: true,
    };
  }
}

export async function triggerGuardianAutoAlertIfConfigured(report) {
  const cfg = getGuardianConfig();
  if (!cfg.guardianName || !cfg.autoCritical) return;

  try {
    const res = await ApiClient.createGuardianAlert({
      scan_id: report.scan_id,
      senior_name: cfg.seniorName,
      guardian_name: cfg.guardianName,
      guardian_phone: cfg.guardianPhone,
      alert_mode: 'AUTO_CRITICAL_ALERT',
      target_url: report.target_url || report.primary_url || '',
      message_excerpt: report.citizen_verdict?.summary || 'Amenaza crítica bloqueada',
      risk_score: report.risk_score,
      risk_level: 'CRITICAL',
    });

    const data = res.data;
    saveLastGuardianToken(data.consultation.token);
    renderGuardianStatusBanner(data.consultation, data.review_url, data.whatsapp_share_url, true);
    startGuardianPolling(data.consultation.token);
    showToast(`Alerta Crítica preparada para tu Ángel Guardián (${cfg.guardianName}).`);
  } catch {
    // Continuar silenciosamente si hay límite de tasa
  }
}

export async function askGuardianOneTap(payload) {
  const cfg = getGuardianConfig();
  const guardianName = cfg.guardianName || 'Familiar de Confianza';

  try {
    const res = await ApiClient.createGuardianAlert({
      scan_id: payload.scan_id || null,
      senior_name: cfg.seniorName,
      guardian_name: guardianName,
      guardian_phone: cfg.guardianPhone,
      alert_mode: payload.alert_mode || 'ASK_GUARDIAN',
      target_url: payload.target_url || '',
      message_excerpt: payload.message_excerpt || 'Solicitud de ayuda con un enlace o mensaje dudoso.',
      risk_score: typeof payload.risk_score === 'number' ? payload.risk_score : 65,
      risk_level: payload.risk_level || 'WARNING',
    });

    const { consultation, review_url, whatsapp_share_url } = res.data;
    saveLastGuardianToken(consultation.token);
    renderGuardianStatusBanner(consultation, review_url, whatsapp_share_url, false);
    startGuardianPolling(consultation.token);

    const sectionEl = document.getElementById('guardian-card-anchor');
    if (sectionEl) {
      sectionEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
    showToast(`Consulta creada para ${guardianName}. Puedes enviársela por WhatsApp en 1 toque.`);
  } catch (err) {
    showToast(err.message || 'No se pudo generar la consulta familiar.', true);
  }
}

function saveLastGuardianToken(token) {
  try {
    localStorage.setItem(STORAGE_KEYS.LAST_GUARDIAN_TOKEN, token);
  } catch {
    // ignore
  }
}

function renderGuardianStatusBanner(consultation, reviewUrl, whatsappUrl, isAutoAlert = false) {
  const box = document.getElementById('guardian-live-status-box');
  if (!box) return;

  box.className = `guardian-live-status visible decision-${consultation.guardian_decision}`;
  box.textContent = '';

  const title = document.createElement('strong');
  title.style.display = 'block';
  title.style.fontSize = '1.05rem';
  title.style.color = '#FFFFFF';

  if (consultation.guardian_decision === 'DANGER_DELETE') {
    title.textContent = `${consultation.guardian_name} respondió: "¡PELIGRO, BÓRRALO YA!"`;
  } else if (consultation.guardian_decision === 'SAFE_APPROVED') {
    title.textContent = `${consultation.guardian_name} respondió: "ES SEGURO, TRANQUILO/A"`;
  } else {
    title.textContent = isAutoAlert
      ? `Alerta Automática de Peligro Crítico lista para ${consultation.guardian_name}`
      : `Esperando respuesta de ${consultation.guardian_name} (Código ${consultation.token})`;
  }

  const note = document.createElement('p');
  note.style.margin = '6px 0 12px';
  note.style.color = '#E2E8F0';
  note.style.fontSize = '0.95rem';
  note.textContent =
    consultation.guardian_note ||
    'Envía el enlace por WhatsApp a tu familiar para que lo revise y te responda con un botón.';

  const actions = document.createElement('div');
  actions.style.display = 'flex';
  actions.style.flexWrap = 'wrap';
  actions.style.gap = '8px';

  if (whatsappUrl) {
    const waLink = document.createElement('a');
    waLink.href = whatsappUrl;
    waLink.target = '_blank';
    waLink.rel = 'noopener noreferrer';
    waLink.className = 'btn btn-sm btn-guardian-ask';
    waLink.textContent = `Enviar por WhatsApp a ${consultation.guardian_name}`;
    actions.appendChild(waLink);
  }

  const previewUrl = reviewUrl || `/guardian?token=${encodeURIComponent(consultation.token)}`;
  const openFamilyView = document.createElement('a');
  openFamilyView.href = previewUrl;
  openFamilyView.target = '_blank';
  openFamilyView.rel = 'noopener noreferrer';
  openFamilyView.className = 'btn btn-outline-cyan btn-sm';
  openFamilyView.textContent = 'Abrir Vista del Familiar';
  actions.appendChild(openFamilyView);

  const checkBtn = document.createElement('button');
  checkBtn.type = 'button';
  checkBtn.className = 'btn btn-ghost btn-sm';
  checkBtn.textContent = 'Revisar si ya respondió';
  checkBtn.addEventListener('click', () => checkGuardianStatusOnce(consultation.token, true));
  actions.appendChild(checkBtn);

  box.append(title, note, actions);
}

async function checkGuardianStatusOnce(token, announceIfPending = false) {
  if (!token) return;
  try {
    const res = await ApiClient.getGuardianConsultation(token);
    const c = res.data.consultation;
    renderGuardianStatusBanner(c, `/guardian?token=${encodeURIComponent(c.token)}`, '');

    if (c.guardian_decision !== 'PENDING') {
      if (guardianPollInterval) {
        clearInterval(guardianPollInterval);
        guardianPollInterval = null;
      }
      const msg =
        c.guardian_decision === 'DANGER_DELETE'
          ? `Atención. ${c.guardian_name} revisó el mensaje y dice: Peligro, bórralo ya. ${c.guardian_note || ''}`
          : `${c.guardian_name} revisó el mensaje y confirma que es seguro. ${c.guardian_note || ''}`;
      showToast(msg, c.guardian_decision === 'DANGER_DELETE');
      if (isAutoVoiceEnabled()) {
        speakTextAloud(msg);
      }
    } else if (announceIfPending) {
      showToast(`${c.guardian_name} aún no ha marcado su respuesta.`);
    }
  } catch {
    // ignore
  }
}

function startGuardianPolling(token) {
  if (guardianPollInterval) {
    clearInterval(guardianPollInterval);
  }
  let checks = 0;
  guardianPollInterval = setInterval(() => {
    checks += 1;
    if (checks > 20) {
      clearInterval(guardianPollInterval);
      guardianPollInterval = null;
      return;
    }
    checkGuardianStatusOnce(token, false);
  }, 6000);
}

/**
 * Inicializa todos los módulos de Protección Adulto Mayor en la página principal
 */
export function initSeniorProtectionSuite({ onScanUrl } = {}) {
  externalUrlScanHandler = onScanUrl || null;

  initSeniorModeToggle();
  initAntiPanicModalControls();
  initGuardianNetworkSection();
  initMessageAndScreenshotAnalyzer();
  initSafeQrScanner();
  initVerifiedDirectory();
  initEmergencyModalAndButtons();
  initTrainingSimulator();
}

function initSeniorModeToggle() {
  const navBtn = document.getElementById('btn-senior-mode-toggle');
  const hubToggleBtn = document.getElementById('btn-hub-senior-mode');
  const autoVoiceChk = document.getElementById('chk-senior-auto-voice');
  const giantPasteBtn = document.getElementById('btn-senior-giant-paste');

  const applyMode = (enabled) => {
    document.documentElement.classList.toggle('senior-mode', enabled);
    try {
      localStorage.setItem(STORAGE_KEYS.SENIOR_MODE, enabled ? '1' : '0');
    } catch {
      // ignore
    }
    if (navBtn) {
      navBtn.setAttribute('aria-pressed', String(enabled));
      const lbl = navBtn.querySelector('[data-senior-label]');
      if (lbl) {
        lbl.textContent = enabled ? 'Modo Adulto Mayor: ACTIVO' : 'Modo Adulto Mayor';
      }
    }
    if (hubToggleBtn) {
      hubToggleBtn.setAttribute('aria-pressed', String(enabled));
      hubToggleBtn.textContent = enabled
        ? 'Desactivar Letra Grande Simplificada'
        : 'Activar Letra Grande y Voz Automática';
    }
  };

  applyMode(isSeniorModeActive());

  if (autoVoiceChk) {
    autoVoiceChk.checked = isAutoVoiceEnabled();
    autoVoiceChk.addEventListener('change', () => {
      try {
        localStorage.setItem(STORAGE_KEYS.AUTO_VOICE, autoVoiceChk.checked ? '1' : '0');
      } catch {
        // ignore
      }
      if (autoVoiceChk.checked) {
        speakTextAloud('Asistente hablado activado. Leeré los resultados con voz clara y pausada.');
      } else {
        stopSpeech();
      }
    });
  }

  const toggleHandler = () => {
    const next = !isSeniorModeActive();
    applyMode(next);
    if (next) {
      try {
        localStorage.setItem(STORAGE_KEYS.AUTO_VOICE, '1');
      } catch {
        // ignore
      }
      if (autoVoiceChk) autoVoiceChk.checked = true;
      showToast('Modo Adulto Mayor activado: letra grande, alto contraste y asistente por voz.');
      speakTextAloud(
        'Modo Adulto Mayor activado. Toca el botón amarillo gigante para pegar y revisar cualquier enlace o mensaje.'
      );
    } else {
      stopSpeech();
      showToast('Vista estándar restaurada.');
    }
  };

  if (navBtn) navBtn.addEventListener('click', toggleHandler);
  if (hubToggleBtn) hubToggleBtn.addEventListener('click', toggleHandler);

  if (giantPasteBtn) {
    giantPasteBtn.addEventListener('click', async () => {
      const heroInput = document.getElementById('hero-url-input');
      let candidate = '';
      try {
        candidate = (await navigator.clipboard.readText()) || '';
      } catch {
        candidate = heroInput?.value || '';
      }
      candidate = candidate.trim();

      if (!candidate && heroInput?.value) {
        candidate = heroInput.value.trim();
      }

      if (!candidate) {
        showToast('Copia primero el mensaje o enlace de WhatsApp y vuelve a tocar el botón amarillo.', true);
        if (heroInput) heroInput.focus();
        return;
      }

      // Si parece un mensaje largo con espacios, enviarlo al analizador completo de mensajes
      if (/\s/.test(candidate) && !/^https?:\/\/\S+$/i.test(candidate)) {
        const msgArea = document.getElementById('senior-message-textarea');
        if (msgArea) {
          msgArea.value = candidate;
          msgArea.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
        await executeSeniorMessageAnalysis(candidate);
      } else {
        if (heroInput) heroInput.value = candidate;
        if (externalUrlScanHandler) {
          externalUrlScanHandler(candidate);
        }
      }
    });
  }
}

function initAntiPanicModalControls() {
  const closeBtn = document.getElementById('anti-panic-close-btn');
  const calmContinueBtn = document.getElementById('anti-panic-continue-btn');
  const speakRulesBtn = document.getElementById('anti-panic-speak-btn');
  const modal = document.getElementById('anti-panic-modal');

  if (closeBtn) closeBtn.addEventListener('click', closeAntiPanicModal);
  if (calmContinueBtn) calmContinueBtn.addEventListener('click', closeAntiPanicModal);
  if (modal) {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) closeAntiPanicModal();
    });
  }
  if (speakRulesBtn) {
    speakRulesBtn.addEventListener('click', () => {
      speakTextAloud(
        'Respira con tranquilidad. Tres reglas de oro para tu seguridad: Primera: Ningún banco ni organismo público pide claves ni códigos por WhatsApp. Segunda: Si alguien escribe diciendo mamá o papá cambié de número, llámalo tú mismo a su número viejo. Tercera: La prisa extrema siempre es trampa. Tu dinero está a salvo si no entregas datos.'
      );
    });
  }
}

function initGuardianNetworkSection() {
  const form = document.getElementById('guardian-config-form');
  const seniorInput = document.getElementById('guardian-senior-name');
  const nameInput = document.getElementById('guardian-family-name');
  const phoneInput = document.getElementById('guardian-family-phone');
  const autoChk = document.getElementById('guardian-auto-critical-chk');
  const askNowBtn = document.getElementById('btn-ask-guardian-direct');

  const cfg = getGuardianConfig();
  if (seniorInput && cfg.seniorName) seniorInput.value = cfg.seniorName;
  if (nameInput && cfg.guardianName) nameInput.value = cfg.guardianName;
  if (phoneInput && cfg.guardianPhone) phoneInput.value = cfg.guardianPhone;
  if (autoChk) autoChk.checked = cfg.autoCritical;

  try {
    const lastToken = localStorage.getItem(STORAGE_KEYS.LAST_GUARDIAN_TOKEN);
    if (lastToken) {
      checkGuardianStatusOnce(lastToken, false);
    }
  } catch {
    // ignore
  }

  if (form) {
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      const sName = seniorInput?.value.trim() || 'Mamá / Papá';
      const gName = nameInput?.value.trim() || 'Familiar de Confianza';
      const gPhone = phoneInput?.value.trim() || '';
      const autoCrit = autoChk ? autoChk.checked : true;

      try {
        localStorage.setItem(STORAGE_KEYS.SENIOR_NAME, sName);
        localStorage.setItem(STORAGE_KEYS.GUARDIAN_NAME, gName);
        localStorage.setItem(STORAGE_KEYS.GUARDIAN_PHONE, gPhone);
        localStorage.setItem(STORAGE_KEYS.GUARDIAN_AUTO_CRITICAL, autoCrit ? '1' : '0');
      } catch {
        // ignore
      }

      showToast(`Ángel Guardián guardado: ${gName}.`);
    });
  }

  if (askNowBtn) {
    askNowBtn.addEventListener('click', () => {
      const msgVal = document.getElementById('senior-message-textarea')?.value.trim() || '';
      const heroVal = document.getElementById('hero-url-input')?.value.trim() || '';
      askGuardianOneTap({
        target_url: heroVal,
        message_excerpt: msgVal || heroVal || 'Recibí un mensaje sospechoso y quiero tu opinión antes de tocarlo.',
        risk_score: 70,
        risk_level: 'WARNING',
        alert_mode: 'ASK_GUARDIAN',
      });
    });
  }
}

function initMessageAndScreenshotAnalyzer() {
  const form = document.getElementById('senior-message-form');
  const textarea = document.getElementById('senior-message-textarea');
  const fileInput = document.getElementById('screenshot-file-input');
  const demoShotBtn = document.getElementById('btn-demo-screenshot');

  document.querySelectorAll('[data-demo-senior-msg]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const msg = btn.getAttribute('data-demo-senior-msg') || '';
      if (textarea && msg) {
        textarea.value = msg;
        executeSeniorMessageAnalysis(msg);
      }
    });
  });

  if (form && textarea) {
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      executeSeniorMessageAnalysis(textarea.value);
    });
  }

  if (fileInput) {
    fileInput.addEventListener('change', async () => {
      const file = fileInput.files?.[0];
      if (!file) return;
      await processScreenshotFile(file);
    });
  }

  if (demoShotBtn) {
    demoShotBtn.addEventListener('click', async () => {
      await runDemoWhatsappScreenshotAnalysis();
    });
  }
}

async function processScreenshotFile(file) {
  const previewFrame = document.getElementById('screenshot-preview-frame');
  const previewImg = document.getElementById('screenshot-preview-img');
  const previewCaption = document.getElementById('screenshot-preview-caption');
  const textarea = document.getElementById('senior-message-textarea');

  const objUrl = URL.createObjectURL(file);
  if (previewImg && previewFrame) {
    previewImg.src = objUrl;
    previewFrame.classList.add('visible');
  }

  let extractedText = '';

  // 1. Intentar detectar Código QR dentro de la captura si BarcodeDetector está disponible
  if ('BarcodeDetector' in window) {
    try {
      const bitmap = await createImageBitmap(file);
      const detector = new window.BarcodeDetector({ formats: ['qr_code'] });
      const codes = await detector.detect(bitmap);
      if (codes && codes.length > 0 && codes[0].rawValue) {
        extractedText = `Código QR detectado en captura: ${codes[0].rawValue}`;
      }
    } catch {
      // Continuar
    }
  }

  // 2. Intentar OCR nativo del dispositivo (Shape Detection TextDetector API en navegadores compatibles)
  if (!extractedText && 'TextDetector' in window) {
    try {
      const bitmap = await createImageBitmap(file);
      const textDetector = new window.TextDetector();
      const blocks = await textDetector.detect(bitmap);
      if (blocks && blocks.length > 0) {
        extractedText = blocks.map((b) => b.rawValue).join(' ');
      }
    } catch {
      // Continuar
    }
  }

  // 3. Revisar metadatos de texto embebidos en capturas PNG
  if (!extractedText && file.type === 'image/png') {
    try {
      const buf = await file.arrayBuffer();
      const pngNote = extractPngTextChunk(new Uint8Array(buf));
      if (pngNote) extractedText = pngNote;
    } catch {
      // ignore
    }
  }

  if (extractedText) {
    if (previewCaption) {
      previewCaption.textContent = 'Texto extraído automáticamente de la captura para análisis forense.';
    }
    if (textarea) textarea.value = extractedText;
    await executeSeniorMessageAnalysis(extractedText);
  } else {
    if (previewCaption) {
      previewCaption.textContent =
        'Captura cargada en pantalla. Copia o escribe abajo la frase principal del mensaje para completar la revisión.';
    }
    if (textarea) {
      textarea.focus();
      showToast('Captura cargada. Pega el texto del mensaje o escribe las palabras clave para analizarlo.');
    }
  }
}

function extractPngTextChunk(bytes) {
  const decoder = new TextDecoder('latin1');
  const raw = decoder.decode(bytes);
  const marker = 'D360_OCR:';
  const idx = raw.indexOf(marker);
  if (idx === -1) return '';
  const slice = raw.slice(idx + marker.length, idx + marker.length + 380);
  return slice.split('\0')[0].trim();
}

async function runDemoWhatsappScreenshotAnalysis() {
  const previewFrame = document.getElementById('screenshot-preview-frame');
  const previewImg = document.getElementById('screenshot-preview-img');
  const previewCaption = document.getElementById('screenshot-preview-caption');
  const textarea = document.getElementById('senior-message-textarea');

  const demoTranscript =
    'Hola mamá, bendición. Se me dañó el teléfono y te escribo desde este número nuevo. Necesito hacer un pago urgente antes de 10 minutos, ¿me puedes transferir?';

  const canvas = document.createElement('canvas');
  canvas.width = 680;
  canvas.height = 300;
  const ctx = canvas.getContext('2d');
  if (ctx) {
    ctx.fillStyle = '#0B141A';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    ctx.fillStyle = '#1F2C34';
    ctx.fillRect(0, 0, canvas.width, 54);
    ctx.fillStyle = '#E9EDEF';
    ctx.font = 'bold 18px sans-serif';
    ctx.fillText('WhatsApp • Número Desconocido (+58 412-900-4411)', 20, 34);

    ctx.fillStyle = '#202C33';
    ctx.fillRect(24, 78, 620, 176);
    ctx.strokeStyle = '#00E1FF';
    ctx.lineWidth = 2;
    ctx.strokeRect(24, 78, 620, 176);

    ctx.fillStyle = '#FFFFFF';
    ctx.font = '18px sans-serif';
    ctx.fillText('Hola mamá, bendición. Se me dañó el teléfono y te', 44, 118);
    ctx.fillText('escribo desde este número nuevo. Necesito hacer un', 44, 148);
    ctx.fillText('pago urgente antes de 10 minutos, ¿me puedes', 44, 178);
    ctx.fillText('transferir a esta cuenta prestada?', 44, 208);

    ctx.fillStyle = '#94A3B8';
    ctx.font = '14px sans-serif';
    ctx.fillText('10:42 a. m. • Mensaje reenviado / remitente no agendado', 44, 238);
  }

  const dataUrl = canvas.toDataURL('image/png');
  if (previewImg && previewFrame) {
    previewImg.src = dataUrl;
    previewFrame.classList.add('visible');
  }
  if (previewCaption) {
    previewCaption.textContent =
      'Captura de WhatsApp procesada por el detector de manipulación psicológica Adulto Mayor.';
  }
  if (textarea) textarea.value = demoTranscript;

  await executeSeniorMessageAnalysis(demoTranscript);
}

export async function executeSeniorMessageAnalysis(messageText) {
  const trimmed = (messageText || '').trim();
  const resultBox = document.getElementById('senior-message-verdict-box');
  const submitBtn = document.getElementById('btn-analyze-senior-msg');

  if (!trimmed) {
    showToast('Pega el mensaje completo o carga una captura de pantalla.', true);
    return;
  }

  if (submitBtn) submitBtn.disabled = true;

  try {
    const res = await ApiClient.analyzeSeniorMessage(trimmed);
    const report = res.data;

    renderSeniorMessageVerdict(report, resultBox);
    await handlePostVerdictSeniorProtections(report);
  } catch (err) {
    showToast(err.message || 'No se pudo analizar el mensaje.', true);
  } finally {
    if (submitBtn) submitBtn.disabled = false;
  }
}

function renderSeniorMessageVerdict(report, box) {
  if (!box) return;
  box.className = `instant-verdict-card visible level-${report.risk_level}`;
  box.textContent = '';

  const badge = document.createElement('span');
  badge.className =
    report.risk_level === 'CRITICAL'
      ? 'badge badge-critical'
      : report.risk_level === 'WARNING'
      ? 'badge badge-warning'
      : 'badge badge-safe';
  badge.textContent =
    report.risk_level === 'CRITICAL'
      ? `PELIGRO CRÍTICO (${report.risk_score}/100)`
      : report.risk_level === 'WARNING'
      ? `PRECAUCIÓN (${report.risk_score}/100)`
      : `MENSAJE SEGURO (${report.risk_score}/100)`;

  const h4 = document.createElement('h3');
  h4.style.marginTop = '10px';
  h4.textContent = report.citizen_verdict.title;

  const p = document.createElement('p');
  p.style.marginTop = '6px';
  p.style.color = '#E2E8F0';
  p.textContent = report.citizen_verdict.summary;

  const ul = document.createElement('ul');
  ul.className = 'instant-reasons-list';
  (report.citizen_verdict.action_steps || []).forEach((step) => {
    const li = document.createElement('li');
    li.textContent = step;
    ul.appendChild(li);
  });

  box.append(badge, h4, p, ul, buildSeniorAssistActionsBar(report));
}

// ----------------------------------------------------------------------------
// ESCÁNER SEGURO DE CÓDIGOS QR (ANTI-QUISHING)
// ----------------------------------------------------------------------------
function initSafeQrScanner() {
  const startCamBtn = document.getElementById('btn-qr-start-camera');
  const stopCamBtn = document.getElementById('btn-qr-stop-camera');
  const qrFileInput = document.getElementById('qr-file-input');
  const demoQrBtn = document.getElementById('btn-qr-demo-scam');

  if (startCamBtn) {
    startCamBtn.addEventListener('click', () => startSafeQrCamera());
  }
  if (stopCamBtn) {
    stopCamBtn.addEventListener('click', () => stopSafeQrCamera());
  }
  if (qrFileInput) {
    qrFileInput.addEventListener('change', async () => {
      const file = qrFileInput.files?.[0];
      if (!file) return;
      await decodeQrFromImageFile(file);
    });
  }
  if (demoQrBtn) {
    demoQrBtn.addEventListener('click', () => runDemoFakeQrInspection());
  }
}

async function startSafeQrCamera() {
  const viewport = document.getElementById('qr-viewport-box');
  const video = document.getElementById('qr-camera-video');
  const canvas = document.getElementById('qr-demo-canvas');
  const statusEl = document.getElementById('qr-scan-status');

  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    showToast('Tu navegador no permite abrir la cámara aquí. Usa "Subir Foto de QR" o la prueba guiada.', true);
    return;
  }

  try {
    stopSafeQrCamera();
    const stream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: 'environment' },
      audio: false,
    });
    activeQrStream = stream;
    if (canvas) canvas.style.display = 'none';
    if (video) {
      video.style.display = 'block';
      video.srcObject = stream;
      await video.play();
    }
    if (viewport) viewport.classList.add('active');
    if (statusEl) {
      statusEl.textContent = 'Cámara activa: apunta al código QR. Detector360 lo revisará sin abrir la página.';
    }

    if ('BarcodeDetector' in window) {
      qrScanLoopActive = true;
      const detector = new window.BarcodeDetector({ formats: ['qr_code'] });
      const tick = async () => {
        if (!qrScanLoopActive || !video) return;
        try {
          const found = await detector.detect(video);
          if (found && found.length > 0 && found[0].rawValue) {
            const rawVal = found[0].rawValue;
            stopSafeQrCamera();
            await inspectDecodedQrPayload(rawVal);
            return;
          }
        } catch {
          // continuar ciclo
        }
        if (qrScanLoopActive) {
          requestAnimationFrame(tick);
        }
      };
      requestAnimationFrame(tick);
    } else if (statusEl) {
      statusEl.textContent =
        'Cámara conectada. Si tu navegador no lee el QR automáticamente, toma una foto o usa el botón de demostración.';
    }
  } catch {
    showToast('No se otorgó permiso de cámara. Puedes subir una imagen del QR o probar la simulación.', true);
  }
}

function stopSafeQrCamera() {
  qrScanLoopActive = false;
  if (activeQrStream) {
    activeQrStream.getTracks().forEach((t) => t.stop());
    activeQrStream = null;
  }
  const video = document.getElementById('qr-camera-video');
  if (video) {
    video.srcObject = null;
    video.style.display = 'none';
  }
}

async function decodeQrFromImageFile(file) {
  const statusEl = document.getElementById('qr-scan-status');
  if (!('BarcodeDetector' in window)) {
    if (statusEl) {
      statusEl.textContent =
        'Este navegador de escritorio no incluye lector óptico QR nativo; prueba desde Chrome en Android o usa "Probar QR de Recibo Falso".';
    }
    showToast('Usa Chrome en tu teléfono Android o prueba el QR de demostración.', true);
    return;
  }

  try {
    const bitmap = await createImageBitmap(file);
    const detector = new window.BarcodeDetector({ formats: ['qr_code'] });
    const codes = await detector.detect(bitmap);
    if (codes && codes.length > 0 && codes[0].rawValue) {
      await inspectDecodedQrPayload(codes[0].rawValue);
    } else {
      showToast('No se encontró ningún código QR claro en la imagen seleccionada.', true);
    }
  } catch {
    showToast('No pudimos leer el código QR de esa imagen.', true);
  }
}

async function runDemoFakeQrInspection() {
  stopSafeQrCamera();
  const viewport = document.getElementById('qr-viewport-box');
  const canvas = document.getElementById('qr-demo-canvas');
  const video = document.getElementById('qr-camera-video');
  if (video) video.style.display = 'none';

  if (canvas && viewport) {
    canvas.style.display = 'block';
    viewport.classList.add('active');
    drawStylizedQrDemo(canvas);
  }

  const fakeQrPayload = 'http://entrega-paquete-pendiente.ejemplo.xyz/pago';
  await inspectDecodedQrPayload(fakeQrPayload);
}

function drawStylizedQrDemo(canvas) {
  canvas.width = 240;
  canvas.height = 240;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  ctx.fillStyle = '#FFFFFF';
  ctx.fillRect(0, 0, 240, 240);
  ctx.fillStyle = '#03153E';

  const drawFinder = (x, y) => {
    ctx.fillRect(x, y, 56, 56);
    ctx.fillStyle = '#FFFFFF';
    ctx.fillRect(x + 8, y + 8, 40, 40);
    ctx.fillStyle = '#03153E';
    ctx.fillRect(x + 16, y + 16, 24, 24);
  };

  drawFinder(16, 16);
  drawFinder(168, 16);
  drawFinder(16, 168);

  for (let r = 0; r < 11; r++) {
    for (let c = 0; c < 11; c++) {
      if ((r < 4 && c < 4) || (r < 4 && c > 6) || (r > 6 && c < 4)) continue;
      if ((r * 7 + c * 13) % 3 === 0) {
        ctx.fillRect(20 + c * 18, 20 + r * 18, 12, 12);
      }
    }
  }
}

async function inspectDecodedQrPayload(rawPayload) {
  const statusEl = document.getElementById('qr-scan-status');
  const trimmed = (rawPayload || '').trim();
  if (statusEl) {
    statusEl.textContent = ` destino oculto en QR interceptado sin abrirlo: ${trimmed.replace(/\./g, '[.]')}`;
  }

  if (/^https?:\/\//i.test(trimmed)) {
    const heroInput = document.getElementById('hero-url-input');
    if (heroInput) {
      heroInput.value = trimmed;
      heroInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
    showToast('Código QR interceptado de forma segura. Ejecutando Rayos X antes de abrirlo...');
    if (externalUrlScanHandler) {
      externalUrlScanHandler(trimmed);
    }
  } else {
    await executeSeniorMessageAnalysis(`Contenido leído en Código QR: ${trimmed}`);
  }
}

// ----------------------------------------------------------------------------
// DIRECTORIO BLANCO VERIFICADO DE BANCOS, ORGANISMOS Y ENVÍOS
// ----------------------------------------------------------------------------
async function initVerifiedDirectory() {
  const searchInput = document.getElementById('directory-search-input');
  const catButtons = document.querySelectorAll('[data-dir-cat]');

  let debounce = null;
  if (searchInput) {
    searchInput.addEventListener('input', () => {
      clearTimeout(debounce);
      debounce = setTimeout(() => {
        loadDirectoryItems(searchInput.value, currentDirectoryCategory);
      }, 200);
    });
  }

  catButtons.forEach((btn) => {
    btn.addEventListener('click', () => {
      currentDirectoryCategory = btn.getAttribute('data-dir-cat') || 'ALL';
      catButtons.forEach((b) => b.classList.toggle('btn-primary', b === btn));
      catButtons.forEach((b) => b.classList.toggle('btn-ghost', b !== btn));
      loadDirectoryItems(searchInput?.value || '', currentDirectoryCategory);
    });
  });

  await loadDirectoryItems('', 'ALL');
}

async function loadDirectoryItems(query, category) {
  const grid = document.getElementById('verified-directory-grid');
  if (!grid) return;

  try {
    const res = await ApiClient.searchVerifiedDirectory(query, category);
    const items = res.data.items || [];
    grid.textContent = '';

    if (items.length === 0) {
      const empty = document.createElement('p');
      empty.style.color = '#C8DDF8';
      empty.textContent =
        'No encontramos esa entidad en el Directorio Blanco. Ten mucho cuidado si te contactaron por un número no listado.';
      grid.appendChild(empty);
      return;
    }

    items.forEach((item) => {
      const card = document.createElement('article');
      card.className = 'directory-verified-card';

      const title = document.createElement('strong');
      title.style.fontSize = '1.05rem';
      title.style.color = '#FFFFFF';
      title.textContent = item.entity_name;

      const domainPill = document.createElement('div');
      domainPill.className = 'directory-domain-pill';
      domainPill.textContent = `Web Oficial Única: ${item.official_domain}`;

      const neverNote = document.createElement('div');
      neverNote.className = 'directory-never-note';
      neverNote.textContent = item.never_asks_notice;

      const callRow = document.createElement('div');
      callRow.className = 'directory-call-row';

      const telClean = item.emergency_phone.replace(/[^\d+]/g, '');
      const callBtn = document.createElement('a');
      callBtn.href = `tel:${telClean}`;
      callBtn.className = 'btn btn-primary btn-sm';
      callBtn.textContent = `Llamar Línea Oficial: ${item.emergency_phone}`;

      const visitBtn = document.createElement('a');
      visitBtn.href = item.official_url;
      visitBtn.target = '_blank';
      visitBtn.rel = 'noopener noreferrer';
      visitBtn.className = 'btn btn-outline-cyan btn-sm';
      visitBtn.textContent = 'Ir a Web Verificada';

      callRow.append(callBtn, visitBtn);
      card.append(title, domainPill, neverNote, callRow);
      grid.appendChild(card);
    });
  } catch {
    // ignore
  }
}

// ----------------------------------------------------------------------------
// BOTÓN DE EMERGENCIA "¿YA DISTE TU CLAVE O HICISTE UN PAGO?"
// ----------------------------------------------------------------------------
function initEmergencyModalAndButtons() {
  const openBtns = document.querySelectorAll('[data-open-senior-emergency]');
  const closeBtn = document.getElementById('senior-emergency-close');
  const modal = document.getElementById('senior-emergency-modal');
  const bankSelect = document.getElementById('emergency-bank-select');
  const callBankLink = document.getElementById('emergency-call-bank-btn');
  const form = document.getElementById('senior-emergency-form');

  openBtns.forEach((btn) => {
    btn.addEventListener('click', () => openSeniorEmergencyModal(''));
  });

  if (closeBtn) {
    closeBtn.addEventListener('click', () => {
      if (modal) modal.classList.remove('open');
    });
  }

  if (modal) {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) modal.classList.remove('open');
    });
  }

  const syncBankCallBtn = () => {
    const slug = bankSelect?.value || 'banesco';
    const info = EMERGENCY_PHONES_BY_SLUG[slug] || EMERGENCY_PHONES_BY_SLUG.banesco;
    if (callBankLink) {
      callBankLink.href = `tel:${info.phone.replace(/[^\d+]/g, '')}`;
      callBankLink.textContent = `PASO 1: Llamar AHORA a ${info.name} (${info.phone})`;
    }
  };

  if (bankSelect) {
    bankSelect.addEventListener('change', syncBankCallBtn);
    syncBankCallBtn();
  }

  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const submitBtn = document.getElementById('emergency-submit-cicpc-btn');
      const resultBox = document.getElementById('emergency-case-result');
      if (submitBtn) submitBtn.disabled = true;

      try {
        const scanIdField = document.getElementById('emergency-scan-id-hidden');
        const payload = {
          scan_id: scanIdField?.value || '',
          bank_slug: bankSelect?.value || 'banesco',
          incident_impact:
            document.getElementById('emergency-impact-select')?.value || 'CREDENTIALS_EXPOSED',
          reporter_contact:
            document.getElementById('emergency-reporter-phone')?.value.trim() || '',
          suspect_info:
            document.getElementById('emergency-suspect-input')?.value.trim() || '',
        };

        const res = await ApiClient.submitSeniorEmergency(payload);
        const data = res.data;

        if (resultBox) {
          resultBox.style.display = 'block';
          resultBox.textContent = '';

          const strong = document.createElement('strong');
          strong.style.display = 'block';
          strong.style.color = '#6EE7B7';
          strong.style.fontSize = '1.05rem';
          strong.textContent = `Expediente Urgente Recibido por C.I.C.P.C: ${data.case_number}`;

          const p = document.createElement('p');
          p.style.margin = '6px 0 0';
          p.style.color = '#FFFFFF';
          p.textContent = `Prioridad asignada: ${data.priority}. No borres los mensajes de WhatsApp y comunícate ya al ${data.emergency_phone} para bloquear tu cuenta.`;

          resultBox.append(strong, p);
        }

        showToast(`Expediente urgente ${data.case_number} registrado en C.I.C.P.C.`);
        if (isAutoVoiceEnabled()) {
          speakTextAloud(
            `Tu reporte urgente fue enviado al C I C P C con expediente ${data.case_number}. Toca el botón rojo superior para llamar ahora mismo a tu banco al ${data.emergency_phone}.`
          );
        }
      } catch (err) {
        showToast(err.message || 'No se pudo enviar el reporte de emergencia.', true);
      } finally {
        if (submitBtn) submitBtn.disabled = false;
      }
    });
  }
}

export function openSeniorEmergencyModal(scanId = '') {
  const modal = document.getElementById('senior-emergency-modal');
  const hiddenScan = document.getElementById('emergency-scan-id-hidden');
  const resultBox = document.getElementById('emergency-case-result');
  if (hiddenScan) hiddenScan.value = scanId || '';
  if (resultBox) resultBox.style.display = 'none';
  if (modal) modal.classList.add('open');
}

// ----------------------------------------------------------------------------
// SIMULADOR DE ENTRENAMIENTO LIGERO (3 PREGUNTAS CON CASOS REALES)
// ----------------------------------------------------------------------------
async function initTrainingSimulator() {
  const scamBtn = document.getElementById('sim-btn-scam');
  const safeBtn = document.getElementById('sim-btn-safe');
  const nextBtn = document.getElementById('sim-btn-next');
  const speakBtn = document.getElementById('sim-btn-speak');

  try {
    const res = await ApiClient.getSeniorSimulator();
    simulatorQuestions = res.data.questions || [];
    simulatorIndex = 0;
    simulatorScore = 0;
    renderCurrentSimulatorQuestion();
  } catch {
    // ignore
  }

  if (scamBtn) {
    scamBtn.addEventListener('click', () => evaluateSimulatorChoice('SCAM'));
  }
  if (safeBtn) {
    safeBtn.addEventListener('click', () => evaluateSimulatorChoice('SAFE'));
  }
  if (nextBtn) {
    nextBtn.addEventListener('click', () => {
      if (simulatorIndex < simulatorQuestions.length - 1) {
        simulatorIndex += 1;
        renderCurrentSimulatorQuestion();
      } else {
        simulatorIndex = 0;
        simulatorScore = 0;
        renderCurrentSimulatorQuestion();
      }
    });
  }
  if (speakBtn) {
    speakBtn.addEventListener('click', () => {
      const q = simulatorQuestions[simulatorIndex];
      if (q) {
        speakTextAloud(`Caso de práctica ${q.step} de ${simulatorQuestions.length}. ${q.message_text}`);
      }
    });
  }
}

function renderCurrentSimulatorQuestion() {
  const q = simulatorQuestions[simulatorIndex];
  if (!q) return;

  const progressEl = document.getElementById('sim-step-label');
  const senderEl = document.getElementById('sim-sender-label');
  const msgEl = document.getElementById('sim-message-text');
  const feedbackBox = document.getElementById('sim-feedback-box');
  const scamBtn = document.getElementById('sim-btn-scam');
  const safeBtn = document.getElementById('sim-btn-safe');

  if (progressEl) {
    progressEl.textContent = `Reto Práctico ${q.step} de ${simulatorQuestions.length} • Canal: ${q.channel}`;
  }
  if (senderEl) senderEl.textContent = `Remitente: ${q.sender_label}`;
  if (msgEl) msgEl.textContent = q.message_text;
  if (feedbackBox) {
    feedbackBox.classList.remove('visible');
    feedbackBox.textContent = '';
  }
  if (scamBtn) scamBtn.disabled = false;
  if (safeBtn) safeBtn.disabled = false;
}

function evaluateSimulatorChoice(choice) {
  const q = simulatorQuestions[simulatorIndex];
  const feedbackBox = document.getElementById('sim-feedback-box');
  const nextBtn = document.getElementById('sim-btn-next');
  const scamBtn = document.getElementById('sim-btn-scam');
  const safeBtn = document.getElementById('sim-btn-safe');
  if (!q || !feedbackBox) return;

  if (scamBtn) scamBtn.disabled = true;
  if (safeBtn) safeBtn.disabled = true;

  const isCorrect = choice === q.correct_answer;
  if (isCorrect) simulatorScore += 1;

  feedbackBox.classList.add('visible');
  feedbackBox.style.background = isCorrect
    ? 'rgba(6, 78, 59, 0.85)'
    : 'rgba(120, 53, 15, 0.88)';
  feedbackBox.textContent = '';

  const headline = document.createElement('strong');
  headline.style.display = 'block';
  headline.style.fontSize = '1.08rem';
  headline.textContent = isCorrect
    ? '¡Respuesta Acertada! Tienes buen ojo contra estafas.'
    : 'Observa este detalle clave para la próxima vez (sin preocuparte):';

  const clue = document.createElement('p');
  clue.style.margin = '6px 0';
  clue.style.color = '#FDE047';
  clue.textContent = `Señal clave: ${q.clue_highlight}`;

  const exp = document.createElement('p');
  exp.style.margin = '6px 0 0';
  exp.textContent = q.explanation_calm;

  feedbackBox.append(headline, clue, exp);

  const isLast = simulatorIndex >= simulatorQuestions.length - 1;
  if (isLast) {
    const summary = document.createElement('p');
    summary.style.marginTop = '10px';
    summary.style.fontWeight = '700';
    summary.style.color = '#6EE7B7';
    summary.textContent = `Entrenamiento completado: ${simulatorScore} de ${simulatorQuestions.length} casos resueltos. ¡Cada práctica protege más a tu familia!`;
    feedbackBox.appendChild(summary);
  }

  if (nextBtn) {
    nextBtn.style.display = 'inline-flex';
    nextBtn.textContent = isLast ? 'Volver a Practicar los 3 Casos' : 'Siguiente Caso Práctico';
  }

  if (isAutoVoiceEnabled()) {
    speakTextAloud(`${headline.textContent} ${q.explanation_calm}`);
  }
}
