import { Router } from 'express';
import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { config } from '../config.js';
import type { Store } from '../db.js';
import { fail } from '../http.js';
import { consumeChallenge, loginSession, storeChallenge } from '../session.js';
import { normalizeUsername } from '../validation.js';

export function authenticationRouter(store: Store): Router {
  const router = Router();

  // Etapa 1 do login: o servidor gera um novo desafio.
  router.post('/options', async (req, res) => {
    // O nome de usuário é opcional. Sem ele, o autenticador exibe as passkeys
    // detectáveis (discoverable) disponíveis para este domínio.
    const username = normalizeUsername(req.body?.username);
    const user = username ? store.getUserByUsername(username) : undefined;

    const options = await generateAuthenticationOptions({
      rpID: config.rpID,
      userVerification: config.userVerification,
      // Usuário inexistente => lista vazia, mesma resposta do fluxo sem nome de usuário
      // (não revela se o nome existe nesta etapa).
      allowCredentials: user
        ? store.listCredentials(user.id).map((c) => ({ id: c.id, transports: c.transports }))
        : undefined,
    });

    storeChallenge(req, 'authentication', options.challenge);
    res.json(options);
  });

  // Etapa 2 do login: o servidor verifica a assinatura sobre o desafio.
  router.post('/verify', async (req, res) => {
    const pending = consumeChallenge(req, 'authentication');
    if (!pending) {
      return fail(res, 400, 'Desafio ausente ou expirado. Reinicie o login.');
    }

    const credentialId: unknown = req.body?.id;
    const stored = typeof credentialId === 'string' ? store.getCredentialById(credentialId) : undefined;
    if (!stored) {
      return fail(res, 401, 'Falha na autenticação.');
    }

    // Em credenciais detectáveis, o authenticator devolve o user handle: deve coincidir.
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
          publicKey: stored.publicKey,
          counter: stored.counter,
          transports: stored.transports,
        },
        requireUserVerification: config.userVerification === 'required',
      });
    } catch (error) {
      console.warn('[login] verificação falhou:', (error as Error).message);
      return fail(res, 401, 'Falha na autenticação.');
    }

    if (!verification.verified) {
      return fail(res, 401, 'Falha na autenticação.');
    }

    const { newCounter, credentialBackedUp } = verification.authenticationInfo;
    store.updateCredentialUsage(stored.id, newCounter, credentialBackedUp);

    const user = store.getUserById(stored.userId);
    if (!user) return fail(res, 401, 'Falha na autenticação.');

    await loginSession(req, user.id);
    res.json({ verified: true, username: user.username });
  });

  return router;
}
