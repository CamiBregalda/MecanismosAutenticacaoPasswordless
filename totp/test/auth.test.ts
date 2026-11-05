import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generate, generateSecret } from 'otplib';
import { checkRecoveryCode, checkTotp } from '../src/auth.js';
import type { AuthDeps } from '../src/auth.js';
import { deriveKeys, encryptSecret, hashRecoveryCode, normalizeRecoveryCode } from '../src/crypto.js';
import { Store } from '../src/db.js';

const NOW_S = 1_700_000_025; // 15 s dentro de um passo
const NOW_MS = NOW_S * 1000;
const MIN = 60 * 1000;
const keys = deriveKeys('chave-de-teste-com-mais-de-32-caracteres!!');

function setup(codes: string[] = []) {
  const store = new Store(':memory:');
  const secret = generateSecret();
  store.createUser('u1', 'camila');
  store.upsertTotp('u1', encryptSecret(secret, 'totp:u1', keys.encKey), 0);
  store.transaction(() =>
    store.replaceRecoveryCodes('u1', codes.map((c) => hashRecoveryCode(normalizeRecoveryCode(c)!, keys.macKey))),
  );
  const deps: AuthDeps = { store, keys, toleranceSeconds: 30 };
  return { store, secret, deps };
}

/** Um código que certamente NÃO é válido nos passos aceitos neste instante. */
async function wrongToken(secret: string, epochS: number): Promise<string> {
  const valid = new Set([
    await generate({ secret, epoch: epochS - 30 }),
    await generate({ secret, epoch: epochS }),
    await generate({ secret, epoch: epochS + 30 }),
  ]);
  for (let i = 0; i < 1000; i++) {
    const candidate = String(i).padStart(6, '0');
    if (!valid.has(candidate)) return candidate;
  }
  throw new Error('inalcançável');
}

test('aceita o código correto e recusa a reutilização do mesmo código', async () => {
  const { deps, secret } = setup();
  const token = await generate({ secret, epoch: NOW_S });
  assert.equal(await checkTotp(deps, 'u1', token, NOW_MS), 'ok');
  assert.equal(await checkTotp(deps, 'u1', token, NOW_MS), 'invalid'); // replay
});

test('um código de passo posterior ao último aceito é aceito', async () => {
  const { deps, secret } = setup();
  const first = await generate({ secret, epoch: NOW_S });
  assert.equal(await checkTotp(deps, 'u1', first, NOW_MS), 'ok');
  const next = await generate({ secret, epoch: NOW_S + 30 });
  assert.equal(await checkTotp(deps, 'u1', next, NOW_MS + 30_000), 'ok');
});

test('cinco códigos inválidos bloqueiam a conta; o código correto não é avaliado', async () => {
  const { deps, store, secret } = setup();
  const bad = await wrongToken(secret, NOW_S);
  for (let i = 0; i < 5; i++) assert.equal(await checkTotp(deps, 'u1', bad, NOW_MS), 'invalid');

  const good = await generate({ secret, epoch: NOW_S });
  assert.equal(await checkTotp(deps, 'u1', good, NOW_MS), 'locked');
  assert.ok(store.listEvents('u1').some((e) => e.type === 'locked'));
});

test('após o bloqueio expirar, o código correto volta a funcionar e o estado é zerado', async () => {
  const { deps, store, secret } = setup();
  const bad = await wrongToken(secret, NOW_S);
  for (let i = 0; i < 5; i++) await checkTotp(deps, 'u1', bad, NOW_MS);

  const later = NOW_MS + 15 * MIN + 1000;
  const good = await generate({ secret, epoch: Math.floor(later / 1000) });
  assert.equal(await checkTotp(deps, 'u1', good, later), 'ok');
  assert.deepEqual(store.getTotp('u1')?.lock, { failedAttempts: 0, lockCount: 0, lockedUntil: 0 });
});

test('o segundo bloqueio é mais longo que o primeiro', async () => {
  const { deps, store, secret } = setup();
  const bad = await wrongToken(secret, NOW_S);
  for (let i = 0; i < 5; i++) await checkTotp(deps, 'u1', bad, NOW_MS);
  const t2 = NOW_MS + 16 * MIN;
  const bad2 = await wrongToken(secret, Math.floor(t2 / 1000));
  for (let i = 0; i < 5; i++) await checkTotp(deps, 'u1', bad2, t2);
  assert.equal(store.getTotp('u1')?.lock.lockedUntil, t2 + 30 * MIN);
});

test('um sucesso zera as falhas consecutivas', async () => {
  const { deps, secret } = setup();
  const bad = await wrongToken(secret, NOW_S);
  for (let i = 0; i < 4; i++) await checkTotp(deps, 'u1', bad, NOW_MS);
  const good = await generate({ secret, epoch: NOW_S });
  assert.equal(await checkTotp(deps, 'u1', good, NOW_MS), 'ok');
  for (let i = 0; i < 4; i++) assert.equal(await checkTotp(deps, 'u1', bad, NOW_MS), 'invalid'); // não bloqueia
});

test('usuário sem autenticador cadastrado é tratado como inválido', async () => {
  const { deps } = setup();
  assert.equal(await checkTotp(deps, 'inexistente', '123456', NOW_MS), 'invalid');
});

test('um segredo cifrado para outro usuário é detectado (falha de integridade)', async () => {
  const { deps, store } = setup();
  store.createUser('u2', 'outra');
  // Copia o segredo cifrado do usuário u1 para u2: o AAD não confere.
  store.upsertTotp('u2', store.getTotp('u1')!.secretEnc, 0);
  await assert.rejects(() => checkTotp(deps, 'u2', '123456', NOW_MS));
});

test('código de recuperação: aceita a digitação flexível e vale uma única vez', () => {
  const { deps } = setup(['ABCDE-FGHJK', 'MNPQR-STVWX']);
  assert.equal(checkRecoveryCode(deps, 'u1', 'abcde fghjk', NOW_MS), 'ok');
  assert.equal(checkRecoveryCode(deps, 'u1', 'ABCDE-FGHJK', NOW_MS), 'invalid'); // já usado
  assert.equal(checkRecoveryCode(deps, 'u1', 'MNPQR-STVWX', NOW_MS), 'ok');
});

test('código de recuperação inválido ou malformado conta como falha e pode bloquear', () => {
  const { deps } = setup(['ABCDE-FGHJK']);
  for (const wrong of ['00000-00000', 'curto', 123, undefined, 'ABCDE-FGHJK-X']) {
    assert.equal(checkRecoveryCode(deps, 'u1', wrong, NOW_MS), 'invalid');
  }
  assert.equal(checkRecoveryCode(deps, 'u1', 'ABCDE-FGHJK', NOW_MS), 'locked'); // 5 falhas => bloqueada
});
