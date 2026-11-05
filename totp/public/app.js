const $ = (id) => document.getElementById(id);

const EVENT_LABELS = {
  enroll: 'Cadastro do autenticador',
  login_totp: 'Login com código TOTP',
  login_recovery: 'Login com código de recuperação',
  login_failed: 'Tentativa inválida',
  locked: 'Conta bloqueada',
  rotate: 'Troca do autenticador',
  recovery_regenerated: 'Novos códigos de recuperação',
};

let recoveryMode = false;

function log(message) {
  const line = document.createElement('div');
  line.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
  $('log').prepend(line);
}

function setStatus(message, kind = '') {
  const el = $('status');
  el.textContent = message; // textContent evita injeção de HTML
  el.className = kind;
}

async function api(path, method = 'GET', body) {
  const response = await fetch(path, {
    method,
    credentials: 'same-origin',
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(data.error || `Erro HTTP ${response.status}`);
    error.code = data.code;
    throw error;
  }
  return data;
}

async function run(button, task) {
  button.disabled = true;
  try {
    await task();
  } catch (error) {
    log(`Falha: ${error.message}`);
    setStatus(error.message, 'error');
  } finally {
    button.disabled = false;
  }
}

// ---- Cadastro -------------------------------------------------------------

async function enrollStart() {
  log('Cadastro: solicitando segredo e QR Code ao servidor');
  const data = await api('/api/enroll/start', 'POST', { username: $('reg-username').value });
  $('enroll-qr').src = data.qrDataUrl;
  $('enroll-secret').textContent = data.secret;
  $('enroll-step1').hidden = true;
  $('enroll-step2').hidden = false;
  setStatus('');
  log('Cadastro: escaneie o QR Code e informe o código exibido no aplicativo');
}

async function enrollConfirm() {
  log('Cadastro: enviando o primeiro código para confirmação');
  const data = await api('/api/enroll/confirm', 'POST', { code: $('enroll-code').value });
  $('enroll-secret').textContent = '';
  $('enroll-qr').removeAttribute('src');
  $('enroll-step2').hidden = true;
  $('enroll-codes').textContent = data.recoveryCodes.join('\n');
  $('enroll-step3').hidden = false;
  setStatus('Autenticador confirmado. Guarde os códigos de recuperação.', 'ok');
  log('Cadastro concluído; códigos de recuperação exibidos uma única vez');
}

function enrollDone() {
  $('enroll-codes').textContent = '';
  $('enroll-step3').hidden = true;
  $('enroll-step1').hidden = false;
  $('enroll-saved').checked = false;
  $('btn-enroll-done').disabled = true;
  return refresh();
}

// ---- Login ----------------------------------------------------------------

function toggleRecovery() {
  recoveryMode = !recoveryMode;
  $('login-code-label').textContent = recoveryMode ? 'Código de recuperação (XXXXX-XXXXX)' : 'Código do aplicativo autenticador';
  $('login-code').placeholder = recoveryMode ? 'XXXXX-XXXXX' : '000000';
  $('login-code').value = '';
  $('btn-toggle-recovery').textContent = recoveryMode ? 'Usar código do aplicativo' : 'Usar código de recuperação';
}

async function login() {
  const path = recoveryMode ? '/api/login/recovery' : '/api/login/totp';
  log(recoveryMode ? 'Login: enviando código de recuperação' : 'Login: enviando código TOTP');
  const data = await api(path, 'POST', { username: $('login-username').value, code: $('login-code').value });
  $('login-code').value = '';
  log(`Login aceito para ${data.username}`);
  setStatus('Autenticado com sucesso.', 'ok');
  await refresh();
}

// ---- Conta ----------------------------------------------------------------

function showCodes(codes) {
  $('codes-view').textContent = codes.join('\n');
  $('codes-panel').hidden = false;
}

async function regenerate() {
  const data = await api('/api/recovery/regenerate', 'POST', { code: $('regen-code').value });
  $('regen-code').value = '';
  showCodes(data.recoveryCodes);
  log('Novos códigos de recuperação gerados; os anteriores foram invalidados');
  setStatus('Novos códigos gerados.', 'ok');
  await refresh();
}

async function rotateStart() {
  const data = await api('/api/rotate/start', 'POST', {});
  $('rotate-qr').src = data.qrDataUrl;
  $('rotate-secret').textContent = data.secret;
  $('rotate-step2').hidden = false;
  log('Troca: escaneie o QR Code com o novo aplicativo e informe o código');
}

async function rotateConfirm() {
  const data = await api('/api/rotate/confirm', 'POST', { code: $('rotate-code').value });
  $('rotate-code').value = '';
  $('rotate-secret').textContent = '';
  $('rotate-qr').removeAttribute('src');
  $('rotate-step2').hidden = true;
  showCodes(data.recoveryCodes);
  log('Autenticador substituído; segredo e códigos anteriores invalidados');
  setStatus('Autenticador substituído.', 'ok');
  await refresh();
}

async function refresh() {
  const me = await api('/api/me');
  $('guest').hidden = me.authenticated;
  $('account').hidden = !me.authenticated;
  if (!me.authenticated) {
    $('codes-panel').hidden = true;
    $('codes-view').textContent = '';
    return;
  }

  $('who').textContent = me.username;
  $('method').textContent = { enrollment: 'cadastro', totp: 'código TOTP', recovery: 'código de recuperação' }[me.authMethod] ?? '—';
  $('recovery-left').textContent = String(me.remainingRecoveryCodes);
  $('rotate-hint').hidden = !me.shouldRotate;

  const { events } = await api('/api/events');
  const body = $('events');
  body.replaceChildren();
  for (const event of events) {
    const row = document.createElement('tr');
    for (const text of [event.createdAt, EVENT_LABELS[event.type] ?? event.type, event.detail ?? '']) {
      const cell = document.createElement('td');
      cell.textContent = text;
      row.append(cell);
    }
    body.append(row);
  }
}

$('btn-enroll-start').addEventListener('click', (e) => run(e.currentTarget, enrollStart));
$('btn-enroll-confirm').addEventListener('click', (e) => run(e.currentTarget, enrollConfirm));
$('enroll-saved').addEventListener('change', (e) => {
  $('btn-enroll-done').disabled = !e.currentTarget.checked;
});
$('btn-enroll-done').addEventListener('click', (e) => run(e.currentTarget, enrollDone));
$('btn-login').addEventListener('click', (e) => run(e.currentTarget, login));
$('btn-toggle-recovery').addEventListener('click', toggleRecovery);
$('btn-regen').addEventListener('click', (e) => run(e.currentTarget, regenerate));
$('btn-rotate-start').addEventListener('click', (e) => run(e.currentTarget, rotateStart));
$('btn-rotate-confirm').addEventListener('click', (e) => run(e.currentTarget, rotateConfirm));
$('btn-logout').addEventListener('click', (e) =>
  run(e.currentTarget, async () => {
    await api('/api/logout', 'POST');
    log('Sessão encerrada');
    setStatus('');
    await refresh();
  }),
);

refresh().catch((error) => setStatus(error.message, 'error'));
