import { test } from 'node:test';
import assert from 'node:assert/strict';
import { RateLimiter } from '../src/rateLimit.js';
import { isRecent } from '../src/middleware.js';

test('permite até o limite e bloqueia o excedente dentro da janela', () => {
  const limiter = new RateLimiter(3, 1000);
  assert.equal(limiter.take('a', 0), true);
  assert.equal(limiter.take('a', 1), true);
  assert.equal(limiter.take('a', 2), true);
  assert.equal(limiter.take('a', 3), false);
});

test('a janela reinicia após expirar', () => {
  const limiter = new RateLimiter(1, 1000);
  assert.equal(limiter.take('a', 0), true);
  assert.equal(limiter.take('a', 999), false);
  assert.equal(limiter.take('a', 1000), true);
});

test('as chaves são independentes', () => {
  const limiter = new RateLimiter(1, 1000);
  assert.equal(limiter.take('a', 0), true);
  assert.equal(limiter.take('b', 0), true);
  assert.equal(limiter.take('a', 1), false);
});

test('isRecent: login recente para operações sensíveis', () => {
  const now = 1_000_000;
  assert.equal(isRecent(undefined, 60_000, now), false);
  assert.equal(isRecent(now - 59_000, 60_000, now), true);
  assert.equal(isRecent(now - 61_000, 60_000, now), false);
  assert.equal(isRecent(now + 1_000, 60_000, now), false);
});
