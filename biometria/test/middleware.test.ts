import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { NextFunction, Request, Response } from 'express';
import { isUvFresh, requireAuth, requireFreshUv } from '../src/middleware.js';

function fakeRes() {
  const res = {
    statusCode: 200,
    body: undefined as unknown,
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(payload: unknown) {
      this.body = payload;
      return this;
    },
  };
  return res;
}

function run(handler: (req: Request, res: Response, next: NextFunction) => void, session: object) {
  const res = fakeRes();
  let called = false;
  handler({ session } as unknown as Request, res as unknown as Response, () => {
    called = true;
  });
  return { res, called };
}

test('isUvFresh respeita a janela de validade', () => {
  const now = 1_000_000;
  assert.equal(isUvFresh(undefined, 60_000, now), false);
  assert.equal(isUvFresh(now - 10_000, 60_000, now), true);
  assert.equal(isUvFresh(now - 60_000, 60_000, now), true); // limite inclusivo
  assert.equal(isUvFresh(now - 60_001, 60_000, now), false);
  assert.equal(isUvFresh(now + 5_000, 60_000, now), false); // instante no futuro é inválido
});

test('requireAuth bloqueia requisições sem sessão', () => {
  const { res, called } = run(requireAuth, {});
  assert.equal(called, false);
  assert.equal(res.statusCode, 401);
  assert.deepEqual(res.body, { error: 'Não autenticado.', code: 'AUTH_REQUIRED' });
});

test('requireFreshUv: sem sessão => 401', () => {
  const { res, called } = run(requireFreshUv(60_000), {});
  assert.equal(called, false);
  assert.equal(res.statusCode, 401);
});

test('requireFreshUv: sessão sem UV recente => 403 UV_REQUIRED', () => {
  const { res, called } = run(requireFreshUv(60_000), { userId: 'u' });
  assert.equal(called, false);
  assert.equal(res.statusCode, 403);
  assert.equal((res.body as { code: string }).code, 'UV_REQUIRED');
});

test('requireFreshUv: UV expirado => 403', () => {
  const { res, called } = run(requireFreshUv(60_000), { userId: 'u', uvAt: Date.now() - 120_000 });
  assert.equal(called, false);
  assert.equal(res.statusCode, 403);
});

test('requireFreshUv: UV recente => permite a ação', () => {
  const { res, called } = run(requireFreshUv(60_000), { userId: 'u', uvAt: Date.now() - 1_000 });
  assert.equal(called, true);
  assert.equal(res.statusCode, 200);
});
