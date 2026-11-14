import {
  ApiClient,
  clearPendingScanId,
  getPendingScanId,
  initMobileNavbar,
  setPendingScanId,
  showToast,
} from './api-client.js';

document.addEventListener('DOMContentLoaded', () => {
  initMobileNavbar();

  // Capture ?pending_scan_id=... from URL if user came from a report or Hero CTA
  const qs = new URLSearchParams(window.location.search);
  const urlPendingScan = qs.get('pending_scan_id');
  if (urlPendingScan && urlPendingScan.startsWith('scn_')) {
    setPendingScanId(urlPendingScan);
  }

  const activePendingScan = getPendingScanId();
  const pendingBanner = document.getElementById('pending-scan-banner');
  if (pendingBanner && activePendingScan) {
    pendingBanner.classList.add('visible');
  }

  // Show/hide password toggle
  document.querySelectorAll('[data-toggle-password]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-toggle-password');
      const input = document.getElementById(targetId);
      if (!input) return;
      const isPwd = input.type === 'password';
      input.type = isPwd ? 'text' : 'password';
      btn.textContent = isPwd ? 'Ocultar' : 'Mostrar';
    });
  });

  initPasswordStrengthMeter();
  initRegisterForm();
  initLoginForm();
});

function computePasswordStrength(pwd) {
  if (!pwd) return 0;
  let score = 0;
  if (pwd.length >= 8) score++;
  if (/[A-Z]/.test(pwd) && /[a-z]/.test(pwd)) score++;
  if (/\d/.test(pwd)) score++;
  if (/[^A-Za-z0-9]/.test(pwd) || pwd.length >= 12) score++;
  return score;
}

function initPasswordStrengthMeter() {
  const pwdInput = document.getElementById('reg-password');
  const label = document.getElementById('pwd-strength-label');
  if (!pwdInput) return;

  const bars = [
    document.getElementById('pwd-bar-1'),
    document.getElementById('pwd-bar-2'),
    document.getElementById('pwd-bar-3'),
    document.getElementById('pwd-bar-4'),
  ];

  const labels = [
    'Ingresa mínimo 8 caracteres',
    'Seguridad baja — agrega números o mayúsculas',
    'Seguridad aceptable — casi lista',
    'Contraseña fuerte y segura',
    'Nivel máximo de protección ciudadana',
  ];

  pwdInput.addEventListener('input', () => {
    const level = computePasswordStrength(pwdInput.value);
    bars.forEach((bar, idx) => {
      if (!bar) return;
      bar.className = 'pwd-bar-segment';
      if (idx < level) {
        bar.classList.add(`lvl-${level}`);
      }
    });
    if (label) {
      label.textContent = labels[level];
    }
  });
}

function initRegisterForm() {
  const form = document.getElementById('register-form');
  if (!form) return;

  const errorBox = document.getElementById('auth-error-box');
  const submitBtn = document.getElementById('register-submit-btn');

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (errorBox) errorBox.style.display = 'none';

    const alias = document.getElementById('reg-alias')?.value?.trim() || '';
    const email = document.getElementById('reg-email')?.value?.trim() || '';
    const password = document.getElementById('reg-password')?.value || '';
    const termsChecked = document.getElementById('reg-terms')?.checked;

    if (!termsChecked) {
      showError(errorBox, 'Debes aceptar los términos de protección ciudadana para continuar.');
      return;
    }

    if (password.length < 8) {
      showError(errorBox, 'Tu contraseña debe tener al menos 8 caracteres.');
      return;
    }

    if (submitBtn) submitBtn.disabled = true;

    try {
      const pendingScanId = getPendingScanId();
      await ApiClient.register({
        alias,
        email,
        password,
        pending_scan_id: pendingScanId || undefined,
      });

      clearPendingScanId();
      showToast('¡Cuenta creada con éxito! Redirigiendo a tu Escudo Personal...');
      setTimeout(() => {
        window.location.href = '/dashboard?welcome=1';
      }, 400);
    } catch (err) {
      showError(errorBox, err.message || 'No se pudo completar el registro.');
      if (submitBtn) submitBtn.disabled = false;
    }
  });
}

function initLoginForm() {
  const form = document.getElementById('login-form');
  if (!form) return;

  const errorBox = document.getElementById('auth-error-box');
  const submitBtn = document.getElementById('login-submit-btn');

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (errorBox) errorBox.style.display = 'none';

    const email = document.getElementById('login-email')?.value?.trim() || '';
    const password = document.getElementById('login-password')?.value || '';

    if (submitBtn) submitBtn.disabled = true;

    try {
      const pendingScanId = getPendingScanId();
      await ApiClient.login({
        email,
        password,
        pending_scan_id: pendingScanId || undefined,
      });

      clearPendingScanId();
      showToast('Acceso verificado. Abriendo tu panel...');
      setTimeout(() => {
        window.location.href = '/dashboard';
      }, 350);
    } catch (err) {
      showError(errorBox, err.message || 'Correo o contraseña incorrectos.');
      if (submitBtn) submitBtn.disabled = false;
    }
  });
}

function showError(box, msg) {
  if (!box) {
    showToast(msg, true);
    return;
  }
  box.textContent = msg;
  box.style.display = 'block';
}
