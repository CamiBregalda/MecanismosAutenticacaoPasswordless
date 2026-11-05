import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  decryptSecret,
  deriveKeys,
  encryptSecret,
  generateRecoveryCode,
  generateRecoveryCodes,
  hashRecoveryCode,
  newRecoveryCodeSet,
  normalizeRecoveryCode,
} from '../src/crypto.js';

const keys = deriveKeys('chave-de-teste-com-mais-de-32-caracteres!!');

test('as subchaves derivadas são distintas entre si e determinísticas', () => {
  assert.notDeepEqual(keys.encKey, keys.macKey);
  assert.equal(keys.encKey.length, 32);
  assert.deepEqual(deriveKeys('chave-de-teste-com-mais-de-32-caracteres!!').encKey, keys.encKey);
  assert.notDeepEqual(deriveKeys('outra-chave-de-teste-com-32-caracteres!!').encKey, keys.encKey);
});

test('cifra e decifra o segredo (ida e volta)', () => {
  const encrypted = encryptSecret('JBSWY3DPEHPK3PXP', 'totp:user-1', keys.encKey);
  assert.match(encrypted, /^v1\./);
  assert.ok(!encrypted.includes('JBSWY3DPEHPK3PXP'));
  assert.equal(decryptSecret(encrypted, 'totp:user-1', keys.encKey), 'JBSWY3DPEHPK3PXP');
});

test('a mesma entrada gera textos cifrados diferentes (IV aleatório)', () => {
  const a = encryptSecret('JBSWY3DPEHPK3PXP', 'totp:user-1', keys.encKey);
  const b = encryptSecret('JBSWY3DPEHPK3PXP', 'totp:user-1', keys.encKey);
  assert.notEqual(a, b);
});

test('detecta adulteração do texto cifrado', () => {
  const encrypted = encryptSecret('JBSWY3DPEHPK3PXP', 'totp:user-1', keys.encKey);
  const [version, payload] = encrypted.split('.');
  const raw = Buffer.from(payload, 'base64url');
  raw[raw.length - 1] ^= 0x01; // altera um bit
  assert.throws(() => decryptSecret(`${version}.${raw.toString('base64url')}`, 'totp:user-1', keys.encKey));
});

test('o segredo cifrado não pode ser movido para outro usuário (AAD)', () => {
  const encrypted = encryptSecret('JBSWY3DPEHPK3PXP', 'totp:user-1', keys.encKey);
  assert.throws(() => decryptSecret(encrypted, 'totp:user-2', keys.encKey));
});

test('chave incorreta e formatos inválidos são recusados', () => {
  const encrypted = encryptSecret('JBSWY3DPEHPK3PXP', 'totp:user-1', keys.encKey);
  assert.throws(() => decryptSecret(encrypted, 'totp:user-1', deriveKeys('x'.repeat(40)).encKey));
  assert.throws(() => decryptSecret('v2.abc', 'totp:user-1', keys.encKey));
  assert.throws(() => decryptSecret('v1.', 'totp:user-1', keys.encKey));
  assert.throws(() => decryptSecret('v1.curto', 'totp:user-1', keys.encKey));
});

test('códigos de recuperação: formato, unicidade e alfabeto', () => {
  const code = generateRecoveryCode();
  assert.match(code, /^[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}$/);
  const codes = generateRecoveryCodes(10);
  assert.equal(new Set(codes).size, 10);
});

test('normaliza a digitação do usuário (maiúsculas, hífen, espaços, O/I/L)', () => {
  assert.equal(normalizeRecoveryCode('abcde-fghjk'), 'ABCDEFGHJK');
  assert.equal(normalizeRecoveryCode(' abcde fghjk '), 'ABCDEFGHJK');
  assert.equal(normalizeRecoveryCode('OOOOO-IIIII'), '0000011111');
  assert.equal(normalizeRecoveryCode('curto'), null);
  assert.equal(normalizeRecoveryCode('ABCDE-FGHJK-M'), null);
  assert.equal(normalizeRecoveryCode('ABCDE-FGHJU'), null); // "U" não pertence ao alfabeto
  assert.equal(normalizeRecoveryCode(12345), null);
});

test('o HMAC do código é determinístico, depende da chave e não revela o código', () => {
  const h1 = hashRecoveryCode('ABCDEFGHJK', keys.macKey);
  assert.equal(h1, hashRecoveryCode('ABCDEFGHJK', keys.macKey));
  assert.notEqual(h1, hashRecoveryCode('ABCDEFGHJM', keys.macKey));
  assert.notEqual(h1, hashRecoveryCode('ABCDEFGHJK', deriveKeys('x'.repeat(40)).macKey));
  assert.match(h1, /^[0-9a-f]{64}$/);
});

test('o conjunto gerado casa texto claro e HMAC', () => {
  const { plain, hashes } = newRecoveryCodeSet(10, keys.macKey);
  assert.equal(plain.length, 10);
  assert.equal(hashes.length, 10);
  plain.forEach((code, i) => {
    assert.equal(hashes[i], hashRecoveryCode(normalizeRecoveryCode(code)!, keys.macKey));
  });
});
