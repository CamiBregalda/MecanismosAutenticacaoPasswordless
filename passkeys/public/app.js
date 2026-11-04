// O bundle UMD de @simplewebauthn/browser expõe o objeto global SimpleWebAuthnBrowser.
const { startRegistration, startAuthentication, browserSupportsWebAuthn } = SimpleWebAuthnBrowser;

const $ = (id) => document.getElementById(id);

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
  if (!response.ok) throw new Error(data.error || `Erro HTTP ${response.status}`);
  return data;
}

function explain(error) {
  switch (error.name) {
    case 'NotAllowedError':
      return 'Operação cancelada, expirada ou negada no autenticador.';
    case 'InvalidStateError':
      return 'Este autenticador já possui uma passkey para esta conta.';
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

async function register() {
  const username = $('reg-username').value;
  log('Registro: solicitando opções ao servidor (desafio aleatório)');
  const optionsJSON = await api('/api/register/options', 'POST', { username });

  log('Registro: o autenticador cria o par de chaves (verificação do usuário no dispositivo)');
  const attestation = await startRegistration({ optionsJSON });

  log('Registro: enviando a chave pública e a resposta assinada ao servidor');
  const result = await api('/api/register/verify', 'POST', attestation);
  log(`Registro verificado (${result.credential.deviceType}, sincronizada: ${result.credential.backedUp})`);
  setStatus('Passkey criada e sessão iniciada.', 'ok');
  await refresh();
}

async function login() {
  const username = $('login-username').value;
  log('Login: solicitando novo desafio ao servidor');
  const optionsJSON = await api('/api/login/options', 'POST', { username });

  log('Login: o autenticador assina o desafio com a chave privada');
  const assertion = await startAuthentication({ optionsJSON });

  log('Login: enviando a assinatura para verificação');
  const result = await api('/api/login/verify', 'POST', assertion);
  log(`Login verificado para ${result.username}`);
  setStatus('Autenticado com sucesso.', 'ok');
  await refresh();
}

async function refresh() {
  const me = await api('/api/me');
  $('guest').hidden = me.authenticated;
  $('account').hidden = !me.authenticated;
  if (!me.authenticated) return;

  $('who').textContent = me.username;
  const list = $('credentials');
  list.replaceChildren();
  for (const credential of me.credentials) {
    const item = document.createElement('li');
    const kind = credential.deviceType === 'multiDevice' ? 'sincronizável' : 'vinculada ao dispositivo';
    const used = credential.lastUsedAt ?? 'nunca usada';
    item.textContent = `${credential.id.slice(0, 12)}… — ${kind}; contador ${credential.counter}; último uso: ${used} `;
    const remove = document.createElement('button');
    remove.type = 'button';
    remove.className = 'secondary';
    remove.textContent = 'Remover';
    remove.addEventListener('click', () =>
      run(remove, async () => {
        await api(`/api/credentials/${encodeURIComponent(credential.id)}`, 'DELETE');
        log('Passkey removida');
        await refresh();
      }),
    );
    item.append(remove);
    list.append(item);
  }
}

if (!browserSupportsWebAuthn()) {
  $('unsupported').hidden = false;
  $('btn-register').disabled = true;
  $('btn-login').disabled = true;
}

$('btn-register').addEventListener('click', (e) => run(e.currentTarget, register));
$('btn-login').addEventListener('click', (e) => run(e.currentTarget, login));
$('btn-add').addEventListener('click', (e) => run(e.currentTarget, register));
$('btn-logout').addEventListener('click', (e) =>
  run(e.currentTarget, async () => {
    await api('/api/logout', 'POST');
    log('Sessão encerrada');
    setStatus('');
    await refresh();
  }),
);

refresh().catch((error) => setStatus(error.message, 'error'));
