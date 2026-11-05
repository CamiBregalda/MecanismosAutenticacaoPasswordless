import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  INITIAL_LOCK_STATE,
  MAX_FAILURES,
  applyFailure,
  isLocked,
  lockDurationMs,
} from '../src/lockout.js';

const MIN = 60 * 1000;

test('o bloqueio escalona: 15 min, 30 min, 1 h... limitado a 24 h', () => {
  assert.equal(lockDurationMs(1), 15 * MIN);
  assert.equal(lockDurationMs(2), 30 * MIN);
  assert.equal(lockDurationMs(3), 60 * MIN);
  assert.equal(lockDurationMs(4), 120 * MIN);
  assert.equal(lockDurationMs(20), 24 * 60 * MIN);
});

test('as falhas só bloqueiam ao atingir o limite', () => {
  let state = INITIAL_LOCK_STATE;
  for (let i = 1; i < MAX_FAILURES; i++) {
    state = applyFailure(state, 1000);
    assert.equal(isLocked(state, 1000), false);
    assert.equal(state.failedAttempts, i);
  }
  state = applyFailure(state, 1000);
  assert.equal(isLocked(state, 1000), true);
  assert.equal(state.lockedUntil, 1000 + 15 * MIN);
  assert.equal(state.failedAttempts, 0); // o contador zera ao iniciar o bloqueio
  assert.equal(state.lockCount, 1);
});

test('o bloqueio expira no instante previsto', () => {
  let state = INITIAL_LOCK_STATE;
  for (let i = 0; i < MAX_FAILURES; i++) state = applyFailure(state, 0);
  assert.equal(isLocked(state, 15 * MIN - 1), true);
  assert.equal(isLocked(state, 15 * MIN), false);
});

test('um segundo bloqueio dura mais que o primeiro', () => {
  let state = INITIAL_LOCK_STATE;
  for (let i = 0; i < MAX_FAILURES; i++) state = applyFailure(state, 0);
  const t1 = 16 * MIN;
  for (let i = 0; i < MAX_FAILURES; i++) state = applyFailure(state, t1);
  assert.equal(state.lockCount, 2);
  assert.equal(state.lockedUntil, t1 + 30 * MIN);
});

test('applyFailure não altera o estado recebido (função pura)', () => {
  const before = { failedAttempts: 2, lockCount: 0, lockedUntil: 0 };
  applyFailure(before, 0);
  assert.deepEqual(before, { failedAttempts: 2, lockCount: 0, lockedUntil: 0 });
});
