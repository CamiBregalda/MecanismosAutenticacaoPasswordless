import { Router } from 'express';
import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { config } from '../config.js';
import type { Store } from '../db.js';
import { fail } from '../http.js';
import { getPolicy } from '../policy.js';
import { consumeChallenge, loginSession, storeChallenge } from '../session.js';
import { normalizeUsername } from '../validation.js';
import { requiresUserVerification } from '../webauthn.js';

export function authenticationRouter(store: Store): Router {
  const router = Router();

  router.post('/options', async (req, res) => {
    const username = normalizeUsername(req.body?.username);
    const user = username ? store.getUserByUsername(username) : undefined;
    const policy = getPolicy();

    const options = await generateAuthenticationOptions({
      rpID: config.rpID,
      userVerification: policy,
      allowCredentials: user
        ? store.listCredentials(user.id).map((c) => ({ id: c.id, transports: c.transports }))
        : undefined,
    });

    storeChallenge(req, 'authentication', options.challenge, policy);
    res.json(options);
  });

  router.post('/verify', async (req, res) => {
    const pending = consumeChallenge(req, 'authentication');
    if (!pending) return fail(res, 400, 'Desafio ausente ou expirado. Reinicie o login.');

    const credentialId: unknown = req.body?.id;
    const stored = typeof credentialId === 'string' ? store.getCredentialById(credentialId) : undefined;
    if (!stored) return fail(res, 401, 'Falha na autenticação.');

    const userHandle: unknown = req.body?.response?.userHandle;
    if (typeof userHandle === 'string' && userHandle !== stored.userId) {
      return fail(res, 401, 'Falha na autenticação.');
    }

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
      console.warn('[login] verificação falhou:', (error as Error).message);
      return fail(res, 401, 'Falha na autenticação.');
    }

    if (!verification.verified) return fail(res, 401, 'Falha na autenticação.');

    const { newCounter, credentialBackedUp, userVerified } = verification.authenticationInfo;
    store.updateCredentialUsage(stored.id, newCounter, credentialBackedUp, userVerified);

    const user = store.getUserById(stored.userId);
    if (!user) return fail(res, 401, 'Falha na autenticação.');

    store.addEvent({
      userId: user.id,
      type: 'login',
      credentialId: stored.id,
      userVerified,
      policy: pending.userVerification,
    });

    await loginSession(req, user.id, userVerified);
    res.json({ verified: true, username: user.username, userVerified, policy: pending.userVerification });
  });

  return router;
}
