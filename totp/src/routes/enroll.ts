import { Router } from 'express';
import type { RequestHandler } from 'express';
import { randomBytes } from 'node:crypto';
import { config } from '../config.js';
import type { Store } from '../db.js';
import { decryptSecret, encryptSecret, newRecoveryCodeSet } from '../crypto.js';
import type { Keys } from '../crypto.js';
import { fail } from '../http.js';
import { qrDataUrl } from '../qr.js';
import {
  clearPending,
  getPending,
  loginSession,
  registerPendingFailure,
  startPending,
} from '../session.js';
import { TOTP_PARAMS, buildOtpauthUri, newSecret, normalizeToken, verifyToken } from '../totp.js';
import { normalizeUsername } from '../validation.js';

interface Deps {
  store: Store;
  keys: Keys;
  limiter: RequestHandler;
}

export function enrollRouter({ store, keys, limiter }: Deps): Router {
  const router = Router();

  // Etapa 1: gera o segredo e o QR Code. Nada é gravado no banco até a confirmação.
  router.post('/start', limiter, async (req, res) => {
    const username = normalizeUsername(req.body?.username);
    if (!username) {
      return fail(res, 400, 'Nome de usuário inválido (3 a 64 caracteres: letras, números, . _ @ -).');
    }
    if (store.getUserByUsername(username)) {
      return fail(res, 409, 'Nome de usuário indisponível.');
    }

    const userId = randomBytes(16).toString('base64url');
    const secret = newSecret();
    startPending(req, {
      kind: 'new',
      userId,
      username,
      secretEnc: encryptSecret(secret, `pending:${userId}`, keys.encKey),
    });

    const uri = buildOtpauthUri({ issuer: config.issuer, account: username, secret });
    res.json({
      otpauthUri: uri,
      qrDataUrl: await qrDataUrl(uri),
      secret, // para digitação manual, caso o usuário não consiga escanear
      issuer: config.issuer,
      ...TOTP_PARAMS,
    });
  });

  // Etapa 2: o usuário prova que o aplicativo está configurado, informando o primeiro código.
  router.post('/confirm', limiter, async (req, res) => {
    const pending = getPending(req, 'new');
    if (!pending) return fail(res, 400, 'Cadastro ausente ou expirado. Reinicie o cadastro.');

    const token = normalizeToken(req.body?.code);
    const secret = decryptSecret(pending.secretEnc, `pending:${pending.userId}`, keys.encKey);
    const check = token
      ? await verifyToken({ secret, token, lastStep: 0, toleranceSeconds: config.toleranceSeconds })
      : { valid: false, step: null };

    if (!check.valid || check.step === null) {
      const exceeded = registerPendingFailure(req);
      return fail(
        res,
        400,
        exceeded
          ? 'Muitas tentativas inválidas. Reinicie o cadastro.'
          : 'Código inválido. Confira o horário do dispositivo e tente o código atual.',
      );
    }

    const { plain, hashes } = newRecoveryCodeSet(config.recoveryCodeCount, keys.macKey);
    try {
      // Usuário, segredo e códigos de recuperação são gravados juntos, ou nenhum deles.
      store.transaction(() => {
        store.createUser(pending.userId, pending.username);
        // O código de confirmação já conta como usado: não pode ser reaproveitado no login.
        store.upsertTotp(pending.userId, encryptSecret(secret, `totp:${pending.userId}`, keys.encKey), check.step!);
        store.replaceRecoveryCodes(pending.userId, hashes);
        store.addEvent(pending.userId, 'enroll', 'autenticador confirmado');
      });
    } catch {
      return fail(res, 409, 'Nome de usuário indisponível.');
    }

    clearPending(req);
    await loginSession(req, pending.userId, 'enrollment');
    // Esta é a ÚNICA vez em que os códigos de recuperação são exibidos.
    res.json({ username: pending.username, recoveryCodes: plain });
  });

  return router;
}
