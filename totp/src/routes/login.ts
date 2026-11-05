import { Router } from 'express';
import type { RequestHandler } from 'express';
import { checkRecoveryCode, checkTotp } from '../auth.js';
import type { AuthDeps } from '../auth.js';
import { fail } from '../http.js';
import { loginSession } from '../session.js';
import { normalizeToken } from '../totp.js';
import { normalizeUsername } from '../validation.js';

// Mensagem ÚNICA para qualquer falha (usuário inexistente, código errado ou conta bloqueada):
// não revela se a conta existe nem se está bloqueada.
const GENERIC_ERROR = 'Credenciais inválidas ou conta temporariamente bloqueada.';

export function loginRouter(deps: AuthDeps, limiter: RequestHandler): Router {
  const router = Router();
  const { store } = deps;

  router.post('/totp', limiter, async (req, res) => {
    const username = normalizeUsername(req.body?.username);
    const token = normalizeToken(req.body?.code);
    const user = username ? store.getUserByUsername(username) : undefined;
    if (!user || !token) return fail(res, 401, GENERIC_ERROR);

    const result = await checkTotp(deps, user.id, token);
    if (result !== 'ok') return fail(res, 401, GENERIC_ERROR);

    store.addEvent(user.id, 'login_totp');
    await loginSession(req, user.id, 'totp');
    res.json({ ok: true, username: user.username });
  });

  router.post('/recovery', limiter, async (req, res) => {
    const username = normalizeUsername(req.body?.username);
    const user = username ? store.getUserByUsername(username) : undefined;
    if (!user) return fail(res, 401, GENERIC_ERROR);

    const result = checkRecoveryCode(deps, user.id, req.body?.code);
    if (result !== 'ok') return fail(res, 401, GENERIC_ERROR);

    store.addEvent(user.id, 'login_recovery', 'código de recuperação consumido');
    await loginSession(req, user.id, 'recovery');
    res.json({
      ok: true,
      username: user.username,
      remainingRecoveryCodes: store.countUnusedRecoveryCodes(user.id),
    });
  });

  return router;
}
