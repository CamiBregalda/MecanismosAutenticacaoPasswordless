// O bundle UMD de @simplewebauthn/browser expõe o objeto global SimpleWebAuthnBrowser.
const {
  startRegistration,
  startAuthentication,
  browserSupportsWebAuthn,
  platformAuthenticatorIsAvailable,
} = SimpleWebAuthnBrowser;

const $ = (id) => document.getElementById(id);

const EVENT_LABELS = {
  register: 'Cadastro do dispositivo',
  login: 'Login',
  step_up: 'Confirmação (step-up)',
  sensitive_action: 'Ação sensível',
};

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

function explain(error) {
  switch (error.name) {
    case 'NotAllowedError':
      return 'Operação cancelada, expirada ou negada. Se a política exige biometria, o dispositivo precisa conseguir verificar o usuário.';
    case 'InvalidStateError':
      return 'Este dispositivo já possui uma credencial para esta conta.';
    case 'SecurityError':
      return 'Origem ou RP ID incompatível. Verifique ORIGIN, RP_ID e o uso de HTTPS.';
    default:
      return error.message;
  }
}

async function run(button, task) {
  button.disabled = true;
  try {
    await task();
  } catch (error) {
    log(`Falha: ${error.name}: ${error.message}`);
    setStatus(explain(error), 'error');
  } finally {
    button.disabled = false;
  }
}

const yesNo = (value) => (value === null ? '—' : value ? 'Sim' : 'Não');

async function loadConfig() {
  const config = await api('/api/config');
  $('env-policy').textContent = config.userVerification;
  $('env-window').textContent = `${config.stepUpWindowSeconds} s`;
  $('lab').hidden = !config.labMode;
  $('policy-select').value = config.userVerification;
}

async function register() {
  const username = $('reg-username').value;
  log('Cadastro: solicitando opções ao servidor (autenticador de plataforma + política de UV)');
  const optionsJSON = await api('/api/register/options', 'POST', { username });

  log('Cadastro: o dispositivo solicita a biometria (ou PIN) e cria o par de chaves');
  const attestation = await startRegistration({ optionsJSON });

  log('Cadastro: enviando a resposta assinada ao servidor');
  const result = await api('/api/register/verify', 'POST', attestation);
  log(`Cadastro verificado. UV informado pelo autenticador: ${yesNo(result.userVerified)} (política: ${result.policy})`);
  setStatus('Dispositivo cadastrado e sessão iniciada.', 'ok');
  await refresh();
}

async function login() {
  const username = $('login-username').value;
  log('Login: solicitando novo desafio ao servidor');
  const optionsJSON = await api('/api/login/options', 'POST', { username });

  log('Login: o dispositivo solicita a biometria (ou PIN) e assina o desafio');
  const assertion = await startAuthentication({ optionsJSON });

  log('Login: enviando a assinatura para verificação');
  const result = await api('/api/login/verify', 'POST', assertion);
  log(`Login verificado. UV informado pelo autenticador: ${yesNo(result.userVerified)} (política: ${result.policy})`);
  setStatus('Autenticado com sucesso.', 'ok');
  await refresh();
}

async function stepUp() {
  log('Step-up: solicitando desafio com verificação do usuário obrigatória');
  const optionsJSON = await api('/api/step-up/options', 'POST');
  log('Step-up: o dispositivo solicita a biometria (ou PIN)');
  const assertion = await startAuthentication({ optionsJSON });
  const result = await api('/api/step-up/verify', 'POST', assertion);
  log(`Step-up verificado. Válido por ${result.validForSeconds} s`);
}

async function sensitiveAction() {
  let result;
  try {
    result = await api('/api/actions/confirm', 'POST', {});
  } catch (error) {
    if (error.code !== 'UV_REQUIRED') throw error;
    log('O servidor exigiu confirmação biométrica recente (UV_REQUIRED)');
    await stepUp();
    log('Repetindo a ação sensível');
    result = await api('/api/actions/confirm', 'POST', {});
  }
  log(`Ação sensível autorizada em ${result.executedAt}`);
  setStatus('Ação sensível autorizada.', 'ok');
  await refresh();
}

async function refresh() {
  const me = await api('/api/me');
  $('guest').hidden = me.authenticated;
  $('account').hidden = !me.authenticated;
  if (!me.authenticated) return;

  $('who').textContent = me.username;
  $('uv-state').textContent = me.uvFresh
    ? `sim (restam ${me.uvRemainingSeconds} s)`
    : 'não (a próxima ação sensível exigirá confirmação)';

  const list = $('credentials');
  list.replaceChildren();
  for (const credential of me.credentials) {
    const item = document.createElement('li');
    const kind = credential.deviceType === 'multiDevice' ? 'sincronizável' : 'vinculada ao dispositivo';
    item.textContent =
      `${credential.id.slice(0, 12)}… — ${kind}; UV no cadastro: ${yesNo(credential.uvAtRegistration)}; ` +
      `UV no último uso: ${yesNo(credential.lastUv)} `;
    const remove = document.createElement('button');
    remove.type = 'button';
    remove.className = 'secondary';
    remove.textContent = 'Remover';
    remove.addEventListener('click', () =>
      run(remove, async () => {
        await api(`/api/credentials/${encodeURIComponent(credential.id)}`, 'DELETE');
        log('Dispositivo removido');
        await refresh();
      }),
    );
    item.append(remove);
    list.append(item);
  }

  const { events } = await api('/api/events');
  const body = $('events');
  body.replaceChildren();
  for (const event of events) {
    const row = document.createElement('tr');
    for (const text of [event.createdAt, EVENT_LABELS[event.type] ?? event.type, yesNo(event.userVerified), event.policy]) {
      const cell = document.createElement('td');
      cell.textContent = text;
      row.append(cell);
    }
    body.append(row);
  }
}

async function init() {
  if (!browserSupportsWebAuthn()) {
    $('unsupported').hidden = false;
    $('btn-register').disabled = true;
    $('btn-login').disabled = true;
    $('env-platform').textContent = 'não';
  } else {
    const available = await platformAuthenticatorIsAvailable();
    $('env-platform').textContent = available
      ? 'sim'
      : 'não detectado (use o autenticador virtual do navegador ou um dispositivo com biometria/PIN)';
  }
  await loadConfig();
  await refresh();
}

$('btn-register').addEventListener('click', (e) => run(e.currentTarget, register));
$('btn-login').addEventListener('click', (e) => run(e.currentTarget, login));
$('btn-add').addEventListener('click', (e) => run(e.currentTarget, register));
$('btn-action').addEventListener('click', (e) => run(e.currentTarget, sensitiveAction));
$('btn-logout').addEventListener('click', (e) =>
  run(e.currentTarget, async () => {
    await api('/api/logout', 'POST');
    log('Sessão encerrada');
    setStatus('');
    await refresh();
  }),
);
$('policy-select').addEventListener('change', (e) =>
  run(e.currentTarget, async () => {
    const result = await api('/api/lab/policy', 'POST', { userVerification: e.currentTarget.value });
    log(`Laboratório: política do servidor alterada para ${result.userVerification}`);
    await loadConfig();
  }),
);

init().catch((error) => setStatus(error.message, 'error'));
