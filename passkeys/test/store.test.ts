import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../src/db.js';

function newStore() {
  return new Store(':memory:');
}

const credentialBase = {
  userId: 'user-1',
  publicKey: new Uint8Array([1, 2, 3, 250, 255]),
  counter: 0,
  transports: ['internal', 'hybrid'],
  deviceType: 'multiDevice' as const,
  backedUp: true,
};

test('cria e recupera usuário (busca sem diferenciar maiúsculas)', () => {
  const store = newStore();
  store.createUser('user-1', 'camila');
  assert.equal(store.getUserByUsername('CAMILA')?.id, 'user-1');
  assert.equal(store.getUserById('user-1')?.username, 'camila');
  assert.equal(store.getUserById('inexistente'), undefined);
});

test('nome de usuário é único', () => {
  const store = newStore();
  store.createUser('user-1', 'camila');
  assert.throws(() => store.createUser('user-2', 'Camila'));
});

test('persiste a chave pública binária sem alterações', () => {
  const store = newStore();
  store.createUser('user-1', 'camila');
  store.addCredential({ ...credentialBase, id: 'cred-1' });
  const stored = store.getCredentialById('cred-1')!;
  assert.deepEqual(Array.from(stored.publicKey), [1, 2, 3, 250, 255]);
  assert.deepEqual(stored.transports, ['internal', 'hybrid']);
  assert.equal(stored.backedUp, true);
  assert.equal(stored.deviceType, 'multiDevice');
  assert.equal(stored.lastUsedAt, null);
});

test('atualiza contador e data de último uso', () => {
  const store = newStore();
  store.createUser('user-1', 'camila');
  store.addCredential({ ...credentialBase, id: 'cred-1' });
  store.updateCredentialUsage('cred-1', 7, false);
  const stored = store.getCredentialById('cred-1')!;
  assert.equal(stored.counter, 7);
  assert.equal(stored.backedUp, false);
  assert.notEqual(stored.lastUsedAt, null);
});

test('credencial exige usuário existente (integridade referencial)', () => {
  const store = newStore();
  assert.throws(() => store.addCredential({ ...credentialBase, id: 'cred-1' }));
});

test('remoção só vale para o dono da credencial', () => {
  const store = newStore();
  store.createUser('user-1', 'camila');
  store.createUser('user-2', 'outra');
  store.addCredential({ ...credentialBase, id: 'cred-1' });
  assert.equal(store.deleteCredential('cred-1', 'user-2'), false);
  assert.equal(store.deleteCredential('cred-1', 'user-1'), true);
  assert.equal(store.listCredentials('user-1').length, 0);
});
