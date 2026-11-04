import { Router } from 'express';
import type { Store } from '../db.js';
import { fail } from '../http.js';
import { logoutSession } from '../session.js';

export function accountRouter(store: Store): Router {
  const router = Router();

  router.get('/me', (req, res) => {
    const user = req.session.userId ? store.getUserById(req.session.userId) : undefined;
    if (!user) {
      res.json({ authenticated: false });
      return;
    }

    res.json({
      authenticated: true,
      username: user.username,
      credentials: store.listCredentials(user.id).map((c) => ({
        id: c.id,
        deviceType: c.deviceType,
        backedUp: c.backedUp,
        transports: c.transports,
        counter: c.counter,
        createdAt: c.createdAt,
        lastUsedAt: c.lastUsedAt,
      })),
    });
  });

  router.post('/logout', async (req, res) => {
    await logoutSession(req);
    res.clearCookie('sid');
    res.json({ ok: true });
  });

  router.delete('/credentials/:id', (req, res) => {
    if (!req.session.userId) return fail(res, 401, 'Não autenticado.');

    const credentials = store.listCredentials(req.session.userId);
    // Impede o bloqueio da conta: a última passkey não pode ser removida.
    if (credentials.length <= 1) {
      return fail(res, 409, 'Não é possível remover a única passkey da conta. Registre outra antes.');
    }
    const removed = store.deleteCredential(req.params.id, req.session.userId);
    if (!removed) return fail(res, 404, 'Credencial não encontrada.');
    res.json({ ok: true });
  });

  return router;
}
