import { Router } from 'express';
import { config } from '../config.js';
import type { Store } from '../db.js';
import { fail } from '../http.js';
import { isUvFresh, requireAuth } from '../middleware.js';
import { logoutSession } from '../session.js';

export function accountRouter(store: Store): Router {
  const router = Router();

  router.get('/me', (req, res) => {
    const user = req.session.userId ? store.getUserById(req.session.userId) : undefined;
    if (!user) {
      res.json({ authenticated: false });
      return;
    }

    const uvAt = req.session.uvAt;
    const fresh = isUvFresh(uvAt, config.stepUpWindowMs);
    const remainingMs = fresh && uvAt ? config.stepUpWindowMs - (Date.now() - uvAt) : 0;

    res.json({
      authenticated: true,
      username: user.username,
      uvFresh: fresh,
      uvRemainingSeconds: Math.max(0, Math.round(remainingMs / 1000)),
      credentials: store.listCredentials(user.id).map((c) => ({
        id: c.id,
        deviceType: c.deviceType,
        backedUp: c.backedUp,
        uvAtRegistration: c.uvAtRegistration,
        lastUv: c.lastUv,
        counter: c.counter,
        createdAt: c.createdAt,
        lastUsedAt: c.lastUsedAt,
      })),
    });
  });

  router.get('/events', requireAuth, (req, res) => {
    res.json({ events: store.listEvents(req.session.userId!) });
  });

  router.post('/logout', async (req, res) => {
    await logoutSession(req);
    res.clearCookie('sid');
    res.json({ ok: true });
  });

  router.delete('/credentials/:id', requireAuth, (req, res) => {
    const userId = req.session.userId!;
    if (store.listCredentials(userId).length <= 1) {
      return fail(res, 409, 'Não é possível remover o único dispositivo da conta. Registre outro antes.');
    }
    const credentialId = req.params.id;
    if (typeof credentialId !== 'string') return fail(res, 400, 'Identificador inválido.');
    if (!store.deleteCredential(credentialId, userId)) {
      return fail(res, 404, 'Credencial não encontrada.');
    }
    res.json({ ok: true });
  });

  return router;
}
