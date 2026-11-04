import { Router } from 'express';
import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { config } from '../config.js';
import type { Store } from '../db.js';
import { fail } from '../http.js';
import { requireAuth } from '../middleware.js';
import { consumeChallenge, storeChallenge } from '../session.js';
import { requiresUserVerification } from '../webauthn.js';

/**
 * Step-up: nova verificação do usuário para quem JÁ está autenticado.
 * Independe da política global: aqui a verificação é SEMPRE obrigatória.
 */
export function stepUpRouter(store: Store): Router {
  const router = Router();
  router.use(requireAuth);

  router.post('/options', async (req, res) => {
    const userId = req.session.userId!;
    const options = await generateAuthenticationOptions({
      rpID: config.rpID,
      userVerification: 'required',
      // Somente as credenciais do próprio usuário autenticado.
      allowCredentials: store
        .listCredentials(userId)
        .map((c) => ({ id: c.id, transports: c.transports })),
    });

    storeChallenge(req, 'step-up', options.challenge, 'required');
    res.json(options);
  });

  router.post('/verify', async (req, res) => {
    const userId = req.session.userId!;
    const pending = consumeChallenge(req, 'step-up');
    if (!pending) return fail(res, 400, 'Desafio ausente ou expirado. Repita a confirmação.');

    const credentialId: unknown = req.body?.id;
    const stored = typeof credentialId === 'string' ? store.getCredentialById(credentialId) : undefined;
    // A credencial usada precisa pertencer ao usuário da sessão.
    if (!stored || stored.userId !== userId) return fail(res, 401, 'Falha na confirmação.');

    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response: req.body,
        expectedChallenge: pending.value,
        expectedOrigin: config.origin,
        expectedRPID: config.rpID,
        credential: {
          id: stored.id,
          publicKey: Uint8Array.from(stored.publicKey),
          counter: stored.counter,
          transports: stored.transports,
        },
        requireUserVerification: requiresUserVerification(pending.userVerification),
      });
    } catch (error) {
      console.warn('[step-up] verificação falhou:', (error as Error).message);
      return fail(res, 401, 'Não foi possível confirmar a identidade com verificação do usuário.');
    }

    if (!verification.verified) return fail(res, 401, 'Falha na confirmação.');

    const { newCounter, credentialBackedUp, userVerified } = verification.authenticationInfo;
    store.updateCredentialUsage(stored.id, newCounter, credentialBackedUp, userVerified);
    store.addEvent({
      userId,
      type: 'step_up',
      credentialId: stored.id,
      userVerified,
      policy: 'required',
    });

    // Só aqui a sessão passa a contar com uma verificação recente.
    req.session.uvAt = Date.now();
    res.json({ verified: true, userVerified, validForSeconds: Math.round(config.stepUpWindowMs / 1000) });
  });

  return router;
}
