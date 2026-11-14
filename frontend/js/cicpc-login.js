import { ApiClient, showToast } from './api-client.js';

document.addEventListener('DOMContentLoaded', async () => {
  // If already authenticated as C.I.C.P.C officer, go directly to command center
  try {
    const session = await ApiClient.cicpcMe();
    if (session?.data?.officer) {
      window.location.replace('/cicpc');
      return;
    }
  } catch {
    // Expected when not logged in yet
  }

  const form = document.getElementById('cicpc-login-form');
  const badgeInput = document.getElementById('cicpc-badge-id');
  const passwordInput = document.getElementById('cicpc-password');
  const keyInput = document.getElementById('cicpc-security-key');
  const submitBtn = document.getElementById('cicpc-login-submit');
  const errorBox = document.getElementById('cicpc-login-error');

  if (!form) return;

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (errorBox) errorBox.style.display = 'none';
    if (submitBtn) submitBtn.disabled = true;

    try {
      const res = await ApiClient.cicpcLogin({
        badge_id: badgeInput?.value || '',
        password: passwordInput?.value || '',
        security_key: keyInput?.value || '',
      });

      showToast(res.message || 'Acceso autorizado.');
      setTimeout(() => {
        window.location.replace('/cicpc');
      }, 280);
    } catch (err) {
      if (errorBox) {
        errorBox.textContent =
          err.message || 'Acceso restringido denegado: Credenciales o clave de seguridad inválidas.';
        errorBox.style.display = 'block';
      }
      if (submitBtn) submitBtn.disabled = false;
    }
  });
});
