import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { Request } from 'express';
import { consumeChallenge, loginSession, storeChallenge } from '../src/session.js';
import { normalizeUsername } from '../src/validation.js';

function fakeRequest() {
  const session: Record<string, unknown> = {
    userId: 'antigo',
    uvAt: 1,
    regenerate(cb: (err: unknown) => void) {
      // express-session cria uma sessão nova: descarta o estado anterior
      for (const key of Object.keys(session)) {
        if (typeof session[key] !== 'function') delete session[key];
      }
      cb(null);
    },
    save(cb: (err: unknown) => void) {
      cb(null);
    },
  };
  return { session } as unknown as Request;
}

test('o desafio é de uso único e carrega a política vigente na emissão', () => {
  const req = fakeRequest();
  storeChallenge(req, 'authentication', 'abc', 'preferred');
  const challenge = consumeChallenge(req, 'authentication');
  assert.equal(challenge?.value, 'abc');
  assert.equal(challenge?.userVerification, 'preferred');
  assert.equal(consumeChallenge(req, 'authentication'), null);
});

test('o desafio não vale para outra finalidade (registro, login e step-up são distintos)', () => {
  const req = fakeRequest();
  storeChallenge(req, 'step-up', 'abc', 'required');
  assert.equal(consumeChallenge(req, 'authentication'), null);
  assert.equal(consumeChallenge(req, 'step-up'), null); // já consumido
});

test('o desafio expira', () => {
  const req = fakeRequest();
  storeChallenge(req, 'registration', 'abc', 'required', { id: 'u', username: 'camila' });
  req.session.challenge!.expiresAt = Date.now() - 1;
  assert.equal(consumeChallenge(req, 'registration'), null);
});

test('loginSession com UV registra o instante da verificação', async () => {
  const req = fakeRequest();
  await loginSession(req, 'user-1', true);
  assert.equal(req.session.userId, 'user-1');
  assert.equal(typeof req.session.uvAt, 'number');
});

test('loginSession sem UV NÃO cria verificação recente (e descarta a anterior)', async () => {
  const req = fakeRequest();
  await loginSession(req, 'user-1', false);
  assert.equal(req.session.userId, 'user-1');
  assert.equal(req.session.uvAt, undefined);
});

test('normaliza e valida nomes de usuário', () => {
  assert.equal(normalizeUsername('  Camila.B  '), 'camila.b');
  assert.equal(normalizeUsername('ab'), null);
  assert.equal(normalizeUsername('<script>'), null);
});
