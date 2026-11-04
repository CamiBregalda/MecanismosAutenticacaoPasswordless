import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseUserVerification, requiresUserVerification } from '../src/webauthn.js';

test('somente a política "required" faz o servidor rejeitar respostas sem UV', () => {
  assert.equal(requiresUserVerification('required'), true);
  assert.equal(requiresUserVerification('preferred'), false);
  assert.equal(requiresUserVerification('discouraged'), false);
});

test('valida valores de política', () => {
  assert.equal(parseUserVerification('required'), 'required');
  assert.equal(parseUserVerification('preferred'), 'preferred');
  assert.equal(parseUserVerification('discouraged'), 'discouraged');
  assert.throws(() => parseUserVerification('obrigatorio'));
  assert.throws(() => parseUserVerification(undefined));
  assert.throws(() => parseUserVerification({ toString: () => 'required' }));
});
