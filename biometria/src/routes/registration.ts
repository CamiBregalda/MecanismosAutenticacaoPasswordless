import { Router } from 'express';
import { randomBytes } from 'node:crypto';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import { config } from '../config.js';
import type { Store } from '../db.js';
import { fail } from '../http.js';
import { getPolicy } from '../policy.js';
import { consumeChallenge, loginSession, storeChallenge } from '../session.js';
import { normalizeUsername } from '../validation.js';
import { SUPPORTED_ALGORITHM_IDS, requiresUserVerification } from '../webauthn.js';

export function registrationRouter(store: Store): Router {
  const router = Router();

  // Etapa 1: o servidor gera as opções, pedindo um autenticador de plataforma e a política de UV.
  router.post('/options', async (req, res) => {
    let user: { id: string; username: string };

    if (req.session.userId) {
      const current = store.getUserById(req.session.userId);
      if (!current) return fail(res, 401, 'Sessão inválida.');
      user = { id: current.id, username: current.username };
    } else {
      const username = normalizeUsername(req.body?.username);
      if (!username) {
        return fail(res, 400, 'Nome de usuário inválido (3 a 64 caracteres: letras, números, . _ @ -).');
      }
      if (store.getUserByUsername(username)) {
        return fail(res, 409, 'Nome de usuário indisponível. Se a conta é sua, entre primeiro e depois adicione outro dispositivo.');
      }
      user = { id: randomBytes(32).toString('base64url'), username };
    }

    const policy = getPolicy();
    const existing = store.listCredentials(user.id);

    const options = await generateRegistrationOptions({
      rpName: config.rpName,
      rpID: config.rpID,
      userName: user.username,
      userDisplayName: user.username,
      userID: new Uint8Array(Buffer.from(user.id, 'base64url')),
      attestationType: 'none',
      excludeCredentials: existing.map((c) => ({ id: c.id, transports: c.transports })),
      authenticatorSelection: {
        // Biometria local: o autenticador deve ser o do próprio dispositivo (sensor + SO).
        authenticatorAttachment: 'platform',
        residentKey: 'required',
        // Pedido ao autenticador. A garantia vem da verificação do flag UV (abaixo).
        userVerification: policy,
      },
      supportedAlgorithmIDs: SUPPORTED_ALGORITHM_IDS,
    });

    storeChallenge(req, 'registration', options.challenge, policy, user);
    res.json(options);
  });

  // Etapa 2: o servidor verifica a resposta e a política de verificação do usuário.
  router.post('/verify', async (req, res) => {
    const pending = consumeChallenge(req, 'registration');
    if (!pending?.pendingUser) {
      return fail(res, 400, 'Desafio ausente ou expirado. Reinicie o registro.');
    }
    const user = pending.pendingUser;

    if (req.session.userId && req.session.userId !== user.id) {
      return fail(res, 403, 'Sessão incompatível com o registro em andamento.');
    }

    let verification;
    try {
      verification = await verifyRegistrationResponse({
        response: req.body,
        expectedChallenge: pending.value,
        expectedOrigin: config.origin,
        expectedRPID: config.rpID,
        // Aplica a MESMA política que foi pedida ao autenticador nas opções.
        requireUserVerification: requiresUserVerification(pending.userVerification),
        supportedAlgorithmIDs: SUPPORTED_ALGORITHM_IDS,
      });
    } catch (error) {
      console.warn('[registro] verificação falhou:', (error as Error).message);
      return fail(res, 400, 'Não foi possível verificar o registro. Se a política exige biometria, o dispositivo precisa realizar a verificação do usuário.');
    }

    if (!verification.verified || !verification.registrationInfo) {
      return fail(res, 400, 'Registro não verificado.');
    }

    const { credential, credentialDeviceType, credentialBackedUp, userVerified } =
      verification.registrationInfo;

    if (!store.getUserById(user.id)) {
      try {
        store.createUser(user.id, user.username);
      } catch {
        return fail(res, 409, 'Nome de usuário indisponível.');
      }
    }

    store.addCredential({
      id: credential.id,
      userId: user.id,
      publicKey: credential.publicKey,
      counter: credential.counter,
      transports: credential.transports ?? [],
      deviceType: credentialDeviceType,
      backedUp: credentialBackedUp,
      uvAtRegistration: userVerified,
    });
    store.addEvent({
      userId: user.id,
      type: 'register',
      credentialId: credential.id,
      userVerified,
      policy: pending.userVerification,
    });

    await loginSession(req, user.id, userVerified);
    res.json({
      verified: true,
      username: user.username,
      userVerified,
      policy: pending.userVerification,
    });
  });

  return router;
}
