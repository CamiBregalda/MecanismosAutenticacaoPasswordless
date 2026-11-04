import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { Request } from 'express';
import { consumeChallenge, storeChallenge } from '../src/session.js';
import { normalizeUsername } from '../src/validation.js';

function fakeRequest() {
  return { session: {} } as unknown as Request;
}

test('o desafio é de uso único', () => {
  const req = fakeRequest();
  storeChallenge(req, 'authentication', 'abc');
  assert.equal(consumeChallenge(req, 'authentication')?.value, 'abc');
  assert.equal(consumeChallenge(req, 'authentication'), null);
});

test('o desafio não vale para outra finalidade', () => {
  const req = fakeRequest();
  storeChallenge(req, 'registration', 'abc', { id: 'u', username: 'camila' });
  assert.equal(consumeChallenge(req, 'authentication'), null);
  // Mesmo erro de finalidade consome o desafio: nova tentativa exige novo desafio.
  assert.equal(consumeChallenge(req, 'registration'), null);
});

test('o desafio expira', () => {
  const req = fakeRequest();
  storeChallenge(req, 'authentication', 'abc');
  req.session.challenge!.expiresAt = Date.now() - 1;
  assert.equal(consumeChallenge(req, 'authentication'), null);
});

test('normaliza e valida nomes de usuário', () => {
  assert.equal(normalizeUsername('  Camila.B  '), 'camila.b');
  assert.equal(normalizeUsername('ab'), null);
  assert.equal(normalizeUsername('com espaço'), null);
  assert.equal(normalizeUsername('<script>'), null);
  assert.equal(normalizeUsername(42), null);
});
