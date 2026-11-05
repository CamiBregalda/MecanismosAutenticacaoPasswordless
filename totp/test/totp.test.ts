import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generate, generateSecret } from 'otplib';
import { buildOtpauthUri, newSecret, normalizeToken, verifyToken } from '../src/totp.js';

// Instante com 15 s decorridos no passo de tempo: longe das fronteiras entre passos.
const NOW_S = 1_700_000_025;
const NOW_MS = NOW_S * 1000;
const STEP = Math.floor(NOW_S / 30);

const secret = generateSecret();

test('o segredo gerado é Base32 e tem ao menos 128 bits', () => {
  const s = newSecret();
  assert.match(s, /^[A-Z2-7]+$/);
  assert.ok(s.length >= 26); // 16 bytes em Base32 sem preenchimento = 26 caracteres
});

test('a URI otpauth traz os parâmetros explícitos e codifica os campos', () => {
  const uri = buildOtpauthUri({ issuer: 'Guia TOTP (TCC)', account: 'camila@exemplo.com', secret: 'JBSWY3DPEHPK3PXP' });
  const url = new URL(uri);
  assert.equal(url.protocol, 'otpauth:');
  assert.equal(url.host, 'totp');
  assert.equal(decodeURIComponent(url.pathname), '/Guia TOTP (TCC):camila@exemplo.com');
  assert.equal(url.searchParams.get('secret'), 'JBSWY3DPEHPK3PXP');
  assert.equal(url.searchParams.get('issuer'), 'Guia TOTP (TCC)');
  assert.equal(url.searchParams.get('algorithm'), 'SHA1');
  assert.equal(url.searchParams.get('digits'), '6');
  assert.equal(url.searchParams.get('period'), '30');
  assert.ok(!uri.includes('+')); // espaços como %20, não "+"
});

test('normalizeToken remove espaços e hifens', () => {
  assert.equal(normalizeToken('123 456'), '123456');
  assert.equal(normalizeToken(' 123-456 '), '123456');
  assert.equal(normalizeToken(''), null);
  assert.equal(normalizeToken(123456), null);
});

test('aceita o código do passo atual e informa o passo', async () => {
  const token = await generate({ secret, epoch: NOW_S });
  const result = await verifyToken({ secret, token, lastStep: 0, toleranceSeconds: 30, nowMs: NOW_MS });
  assert.deepEqual(result, { valid: true, step: STEP });
});

test('aceita o código do passo anterior dentro da tolerância de relógio', async () => {
  const token = await generate({ secret, epoch: NOW_S - 30 });
  const result = await verifyToken({ secret, token, lastStep: 0, toleranceSeconds: 30, nowMs: NOW_MS });
  assert.deepEqual(result, { valid: true, step: STEP - 1 });
});

test('recusa o código de dois passos atrás', async () => {
  const token = await generate({ secret, epoch: NOW_S - 60 });
  const result = await verifyToken({ secret, token, lastStep: 0, toleranceSeconds: 30, nowMs: NOW_MS });
  assert.equal(result.valid, false);
});

test('sem tolerância, o passo anterior é recusado', async () => {
  const token = await generate({ secret, epoch: NOW_S - 30 });
  const result = await verifyToken({ secret, token, lastStep: 0, toleranceSeconds: 0, nowMs: NOW_MS });
  assert.equal(result.valid, false);
});

test('proteção contra reutilização: o mesmo passo não é aceito duas vezes', async () => {
  const token = await generate({ secret, epoch: NOW_S });
  const first = await verifyToken({ secret, token, lastStep: 0, toleranceSeconds: 30, nowMs: NOW_MS });
  assert.equal(first.valid, true);
  const replay = await verifyToken({ secret, token, lastStep: first.step!, toleranceSeconds: 30, nowMs: NOW_MS });
  assert.equal(replay.valid, false);
});

test('um passo anterior ao último aceito também é recusado', async () => {
  const older = await generate({ secret, epoch: NOW_S - 30 });
  const result = await verifyToken({ secret, token: older, lastStep: STEP, toleranceSeconds: 30, nowMs: NOW_MS });
  assert.equal(result.valid, false);
});

test('entradas malformadas resultam em "inválido", sem lançar exceção', async () => {
  for (const token of ['abcdef', '12345', '1234567', '', '12 3456', '١٢٣٤٥٦']) {
    const result = await verifyToken({ secret, token, lastStep: 0, toleranceSeconds: 30, nowMs: NOW_MS });
    assert.equal(result.valid, false, `deveria recusar "${token}"`);
  }
});

test('segredo diferente não valida o código', async () => {
  const token = await generate({ secret: generateSecret(), epoch: NOW_S });
  const result = await verifyToken({ secret, token, lastStep: 0, toleranceSeconds: 30, nowMs: NOW_MS });
  // Probabilidade de colisão: ~3 em 1.000.000. Se ocorrer, repita o teste.
  assert.equal(result.valid, false);
});
