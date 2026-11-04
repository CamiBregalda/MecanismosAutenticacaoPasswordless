import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../src/db.js';

const credentialBase = {
  userId: 'user-1',
  publicKey: new Uint8Array([1, 2, 3, 250, 255]),
  counter: 0,
  transports: ['internal'],
  deviceType: 'multiDevice' as const,
  backedUp: true,
  uvAtRegistration: true,
};

function storeWithUser() {
  const store = new Store(':memory:');
  store.createUser('user-1', 'camila');
  return store;
}

test('persiste a chave pública binária e o resultado de UV no cadastro', () => {
  const store = storeWithUser();
  store.addCredential({ ...credentialBase, id: 'cred-1' });
  const stored = store.getCredentialById('cred-1')!;
  assert.deepEqual(Array.from(stored.publicKey), [1, 2, 3, 250, 255]);
  assert.equal(stored.uvAtRegistration, true);
  assert.equal(stored.lastUv, null); // nunca usada
});

test('registra UV = false quando o autenticador não verificou o usuário', () => {
  const store = storeWithUser();
  store.addCredential({ ...credentialBase, id: 'cred-1', uvAtRegistration: false });
  assert.equal(store.getCredentialById('cred-1')!.uvAtRegistration, false);
});

test('atualiza contador, sincronização e último resultado de UV', () => {
  const store = storeWithUser();
  store.addCredential({ ...credentialBase, id: 'cred-1' });
  store.updateCredentialUsage('cred-1', 5, false, false);
  const stored = store.getCredentialById('cred-1')!;
  assert.equal(stored.counter, 5);
  assert.equal(stored.backedUp, false);
  assert.equal(stored.lastUv, false);
  store.updateCredentialUsage('cred-1', 6, false, true);
  assert.equal(store.getCredentialById('cred-1')!.lastUv, true);
});

test('trilha de eventos: ordem decrescente, limite e flag de UV', () => {
  const store = storeWithUser();
  store.addEvent({ userId: 'user-1', type: 'register', credentialId: 'c', userVerified: true, policy: 'required' });
  store.addEvent({ userId: 'user-1', type: 'login', credentialId: 'c', userVerified: false, policy: 'preferred' });
  store.addEvent({ userId: 'user-1', type: 'sensitive_action', credentialId: null, userVerified: true, policy: 'required' });

  const events = store.listEvents('user-1');
  assert.deepEqual(events.map((e) => e.type), ['sensitive_action', 'login', 'register']);
  assert.equal(events[1].userVerified, false);
  assert.equal(events[2].userVerified, true);
  assert.equal(events[0].credentialId, null);
  assert.equal(store.listEvents('user-1', 2).length, 2);
});

test('eventos de um usuário não aparecem para outro', () => {
  const store = storeWithUser();
  store.createUser('user-2', 'outra');
  store.addEvent({ userId: 'user-1', type: 'login', credentialId: null, userVerified: true, policy: 'required' });
  assert.equal(store.listEvents('user-2').length, 0);
});

test('evento exige usuário existente (integridade referencial)', () => {
  const store = new Store(':memory:');
  assert.throws(() =>
    store.addEvent({ userId: 'inexistente', type: 'login', credentialId: null, userVerified: true, policy: 'required' }),
  );
});

test('remoção de credencial só vale para o dono', () => {
  const store = storeWithUser();
  store.createUser('user-2', 'outra');
  store.addCredential({ ...credentialBase, id: 'cred-1' });
  assert.equal(store.deleteCredential('cred-1', 'user-2'), false);
  assert.equal(store.deleteCredential('cred-1', 'user-1'), true);
});
