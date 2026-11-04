import { Router } from 'express';
import { config } from '../config.js';
import type { Store } from '../db.js';
import { requireFreshUv } from '../middleware.js';

/** Ações sensíveis: só executam com verificação do usuário recente. */
export function actionsRouter(store: Store): Router {
  const router = Router();

  router.post('/confirm', requireFreshUv(config.stepUpWindowMs), (req, res) => {
    store.addEvent({
      userId: req.session.userId!,
      type: 'sensitive_action',
      credentialId: null,
      userVerified: true,
      policy: 'required',
    });
    res.json({ ok: true, message: 'Ação sensível autorizada.', executedAt: new Date().toISOString() });
  });

  return router;
}
