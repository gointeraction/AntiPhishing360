import { ApiClient, showToast } from './api-client.js';

let currentToken = '';

document.addEventListener('DOMContentLoaded', async () => {
  const qs = new URLSearchParams(window.location.search);
  currentToken = (qs.get('token') || '').trim();

  if (!currentToken) {
    showError('No se indicó un código válido de Ángel Guardián.');
    return;
  }

  await loadConsultation(currentToken);
  bindReplyButtons();
});

async function loadConsultation(token) {
  const loadingEl = document.getElementById('guardian-loading');
  const contentEl = document.getElementById('guardian-content');

  try {
    const res = await ApiClient.getGuardianConsultation(token);
    const c = res.data.consultation;

    if (loadingEl) loadingEl.style.display = 'none';
    if (contentEl) contentEl.style.display = 'flex';

    const modeLabel = document.getElementById('guardian-mode-label');
    if (modeLabel) {
      modeLabel.textContent =
        c.alert_mode === 'AUTO_CRITICAL_ALERT'
          ? 'ALERTA AUTOMÁTICA ESCUDO FAMILIAR • PELIGRO CRÍTICO'
          : 'CONSULTA EN 1 TOQUE • ÁNGEL GUARDIÁN';
    }

    const headline = document.getElementById('guardian-headline');
    if (headline) {
      headline.textContent =
        c.alert_mode === 'AUTO_CRITICAL_ALERT'
          ? `Atención ${c.guardian_name}: ${c.senior_name} analizó un enlace de Alto Peligro`
          : `${c.senior_name} te pregunta si puede confiar en este mensaje`;
    }

    const sub = document.getElementById('guardian-subtext');
    if (sub) {
      sub.textContent =
        'Tu respuesta aparecerá de inmediato con letras gigantes y voz hablada en la pantalla de tu familiar.';
    }

    const badge = document.getElementById('guardian-risk-badge');
    if (badge) {
      badge.className =
        c.risk_level === 'CRITICAL'
          ? 'badge badge-critical'
          : c.risk_level === 'WARNING'
          ? 'badge badge-warning'
          : 'badge badge-safe';
      badge.textContent = `Riesgo ${c.risk_score}/100 (${c.risk_level})`;
    }

    if (c.target_url) {
      const urlRow = document.getElementById('guardian-url-row');
      const urlCode = document.getElementById('guardian-target-url');
      if (urlRow) urlRow.style.display = 'block';
      if (urlCode) urlCode.textContent = c.target_url.replace(/\./g, '[.]');
    }

    if (c.message_excerpt) {
      const exRow = document.getElementById('guardian-excerpt-row');
      const exTxt = document.getElementById('guardian-message-excerpt');
      if (exRow) exRow.style.display = 'block';
      if (exTxt) exTxt.textContent = c.message_excerpt;
    }

    if (c.guardian_decision !== 'PENDING') {
      renderReplyConfirmation(c);
    }
  } catch (err) {
    showError(err.message || 'No pudimos cargar la consulta familiar.');
  }
}

function bindReplyButtons() {
  const dangerBtn = document.getElementById('btn-reply-danger');
  const safeBtn = document.getElementById('btn-reply-safe');
  const noteInput = document.getElementById('guardian-note-input');

  if (dangerBtn) {
    dangerBtn.addEventListener('click', () =>
      submitDecision('DANGER_DELETE', noteInput?.value || 'Bórralo de inmediato, es un engaño.')
    );
  }

  if (safeBtn) {
    safeBtn.addEventListener('click', () =>
      submitDecision('SAFE_APPROVED', noteInput?.value || 'Ya lo revisé con calma, es seguro.')
    );
  }
}

async function submitDecision(decision, note) {
  const dangerBtn = document.getElementById('btn-reply-danger');
  const safeBtn = document.getElementById('btn-reply-safe');
  if (dangerBtn) dangerBtn.disabled = true;
  if (safeBtn) safeBtn.disabled = true;

  try {
    const res = await ApiClient.replyGuardianConsultation(currentToken, decision, note);
    showToast(res.message || 'Respuesta familiar registrada.');
    renderReplyConfirmation(res.data.consultation);
  } catch (err) {
    showToast(err.message || 'No se pudo enviar tu respuesta.', true);
  } finally {
    if (dangerBtn) dangerBtn.disabled = false;
    if (safeBtn) safeBtn.disabled = false;
  }
}

function renderReplyConfirmation(c) {
  const box = document.getElementById('guardian-reply-confirmation');
  if (!box) return;

  box.className = `guardian-live-status visible decision-${c.guardian_decision}`;
  box.textContent = '';

  const title = document.createElement('strong');
  title.style.display = 'block';
  title.style.fontSize = '1.1rem';
  title.textContent =
    c.guardian_decision === 'DANGER_DELETE'
      ? `Respuesta enviada a ${c.senior_name}: "PELIGRO, BÓRRALO YA"`
      : `Respuesta enviada a ${c.senior_name}: "ES SEGURO"`;

  const detail = document.createElement('p');
  detail.style.margin = '6px 0 0';
  detail.textContent = c.guardian_note || 'Tu familiar ya puede ver esta indicación en su teléfono.';

  box.append(title, detail);
}

function showError(msg) {
  const loadingEl = document.getElementById('guardian-loading');
  const errEl = document.getElementById('guardian-error');
  const msgEl = document.getElementById('guardian-error-msg');
  if (loadingEl) loadingEl.style.display = 'none';
  if (errEl) errEl.style.display = 'flex';
  if (msgEl) msgEl.textContent = msg;
}
