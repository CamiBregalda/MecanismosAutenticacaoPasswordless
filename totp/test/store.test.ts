import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../src/db.js';

function storeWithUser() {
  const store = new Store(':memory:');
  store.createUser('u1', 'camila');
  return store;
}

test('usuários: busca sem diferenciar maiúsculas e nome único', () => {
  const store = storeWithUser();
  assert.equal(store.getUserByUsername('CAMILA')?.id, 'u1');
  assert.throws(() => store.createUser('u2', 'Camila'));
});

test('segredo: grava, lê e substitui, zerando o bloqueio', () => {
  const store = storeWithUser();
  store.upsertTotp('u1', 'v1.segredo-a', 10);
  store.saveLockState('u1', { failedAttempts: 3, lockCount: 2, lockedUntil: 999 });
  assert.equal(store.getTotp('u1')?.secretEnc, 'v1.segredo-a');
  assert.deepEqual(store.getTotp('u1')?.lock, { failedAttempts: 3, lockCount: 2, lockedUntil: 999 });

  store.upsertTotp('u1', 'v1.segredo-b', 0);
  const record = store.getTotp('u1')!;
  assert.equal(record.secretEnc, 'v1.segredo-b');
  assert.equal(record.lastStep, 0);
  assert.deepEqual(record.lock, { failedAttempts: 0, lockCount: 0, lockedUntil: 0 });
});

test('advanceLastStep só avança: é a base da proteção contra reutilização', () => {
  const store = storeWithUser();
  store.upsertTotp('u1', 'v1.x', 100);
  assert.equal(store.advanceLastStep('u1', 100), false); // mesmo passo
  assert.equal(store.advanceLastStep('u1', 99), false); // passo anterior
  assert.equal(store.advanceLastStep('u1', 101), true);
  assert.equal(store.advanceLastStep('u1', 101), false); // segunda tentativa com o mesmo passo
  assert.equal(store.getTotp('u1')?.lastStep, 101);
});

test('códigos de recuperação: uso único e substituição integral', () => {
  const store = storeWithUser();
  store.transaction(() => store.replaceRecoveryCodes('u1', ['h1', 'h2', 'h3']));
  assert.equal(store.countUnusedRecoveryCodes('u1'), 3);
  assert.equal(store.consumeRecoveryCode('u1', 'h1'), true);
  assert.equal(store.consumeRecoveryCode('u1', 'h1'), false); // já usado
  assert.equal(store.consumeRecoveryCode('u1', 'inexistente'), false);
  assert.equal(store.countUnusedRecoveryCodes('u1'), 2);

  store.transaction(() => store.replaceRecoveryCodes('u1', ['n1']));
  assert.equal(store.countUnusedRecoveryCodes('u1'), 1);
  assert.equal(store.consumeRecoveryCode('u1', 'h2'), false); // código antigo invalidado
});

test('o código de um usuário não vale para outro', () => {
  const store = storeWithUser();
  store.createUser('u2', 'outra');
  store.transaction(() => store.replaceRecoveryCodes('u1', ['h1']));
  assert.equal(store.consumeRecoveryCode('u2', 'h1'), false);
});

test('transação: desfaz tudo se ocorrer erro', () => {
  const store = new Store(':memory:');
  assert.throws(() =>
    store.transaction(() => {
      store.createUser('u1', 'camila');
      store.createUser('u2', 'camila'); // viola a unicidade
    }),
  );
  assert.equal(store.getUserByUsername('camila'), undefined); // nada foi gravado
});

test('eventos: ordem decrescente, limite e isolamento por usuário', () => {
  const store = storeWithUser();
  store.createUser('u2', 'outra');
  store.addEvent('u1', 'enroll');
  store.addEvent('u1', 'login_failed', 'falhas consecutivas: 1');
  store.addEvent('u1', 'login_totp');
  store.addEvent('u2', 'enroll');
  const events = store.listEvents('u1');
  assert.deepEqual(events.map((e) => e.type), ['login_totp', 'login_failed', 'enroll']);
  assert.equal(events[1].detail, 'falhas consecutivas: 1');
  assert.equal(store.listEvents('u1', 2).length, 2);
  assert.equal(store.listEvents('u2').length, 1);
});

test('integridade referencial: segredo exige usuário existente', () => {
  const store = new Store(':memory:');
  assert.throws(() => store.upsertTotp('inexistente', 'v1.x', 0));
});
