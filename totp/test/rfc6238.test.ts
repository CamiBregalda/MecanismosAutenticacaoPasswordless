import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generate } from 'otplib';

/**
 * Teste de CONFORMIDADE da biblioteca com os vetores de teste do RFC 6238 (Apêndice B),
 * para HMAC-SHA-1, segredo ASCII "12345678901234567890" e códigos de 8 dígitos.
 * Garante que a versão instalada da otplib implementa o algoritmo corretamente.
 */
const SECRET = new TextEncoder().encode('12345678901234567890');

const VECTORS: Array<[number, string]> = [
  [59, '94287082'],
  [1111111109, '07081804'],
  [1111111111, '14050471'],
  [1234567890, '89005924'],
  [2000000000, '69279037'],
  [20000000000, '65353130'],
];

for (const [epoch, expected] of VECTORS) {
  test(`RFC 6238, SHA-1, T = ${epoch} s => ${expected}`, async () => {
    const token = await generate({ secret: SECRET, epoch, digits: 8, algorithm: 'sha1', period: 30 });
    assert.equal(token, expected);
  });
}
