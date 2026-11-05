import { Router } from 'express';
import type { RequestHandler } from 'express';
import { checkTotp } from '../auth.js';
import type { AuthDeps } from '../auth.js';
import { config } from '../config.js';
import { decryptSecret, encryptSecret, newRecoveryCodeSet } from '../crypto.js';
import { fail } from '../http.js';
import { requireAuth, requireRecentLogin } from '../middleware.js';
import { qrDataUrl } from '../qr.js';
import {
  clearPending,
  getPending,
  logoutSession,
  registerPendingFailure,
  startPending,
} from '../session.js';
import { TOTP_PARAMS, buildOtpauthUri, newSecret, normalizeToken, verifyToken } from '../totp.js';

export function accountRouter(deps: AuthDeps, limiter: RequestHandler): Router {
  const router = Router();
  const { store, keys } = deps;

  router.get('/me', (req, res) => {
    const user = req.session.userId ? store.getUserById(req.session.userId) : undefined;
    if (!user) {
      res.json({ authenticated: false });
      return;
    }
    res.json({
      authenticated: true,
      username: user.username,
      authMethod: req.session.authMethod,
      remainingRecoveryCodes: store.countUnusedRecoveryCodes(user.id),
      // Quem entrou com código de recuperação provavelmente perdeu o autenticador.
      shouldRotate: req.session.authMethod === 'recovery',
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

  // Gera novos códigos de recuperação. Exige um código TOTP válido (prova de posse do autenticador).
  router.post('/recovery/regenerate', requireAuth, limiter, async (req, res) => {
    const userId = req.session.userId!;
    const token = normalizeToken(req.body?.code);
    if (!token) return fail(res, 400, 'Informe o código atual do aplicativo autenticador.');

    const result = await checkTotp(deps, userId, token);
    if (result !== 'ok') return fail(res, 401, 'Código inválido ou conta temporariamente bloqueada.');

    const { plain, hashes } = newRecoveryCodeSet(config.recoveryCodeCount, keys.macKey);
    store.transaction(() => {
      store.replaceRecoveryCodes(userId, hashes);
      store.addEvent(userId, 'recovery_regenerated', 'códigos anteriores invalidados');
    });
    res.json({ recoveryCodes: plain });
  });

  // Troca do autenticador (aparelho perdido ou substituído). Não exige o código antigo,
  // pois o usuário pode ter entrado justamente com um código de recuperação.
  router.post('/rotate/start', requireRecentLogin(config.recentLoginMs), limiter, async (req, res) => {
    const user = store.getUserById(req.session.userId!);
    if (!user) return fail(res, 401, 'Sessão inválida.');

    const secret = newSecret();
    startPending(req, {
      kind: 'rotate',
      userId: user.id,
      username: user.username,
      secretEnc: encryptSecret(secret, `pending:${user.id}`, keys.encKey),
    });
    const uri = buildOtpauthUri({ issuer: config.issuer, account: user.username, secret });
    res.json({ otpauthUri: uri, qrDataUrl: await qrDataUrl(uri), secret, issuer: config.issuer, ...TOTP_PARAMS });
  });

  router.post('/rotate/confirm', requireRecentLogin(config.recentLoginMs), limiter, async (req, res) => {
    const pending = getPending(req, 'rotate');
    if (!pending || pending.userId !== req.session.userId) {
      return fail(res, 400, 'Troca ausente ou expirada. Reinicie o processo.');
    }

    const token = normalizeToken(req.body?.code);
    const secret = decryptSecret(pending.secretEnc, `pending:${pending.userId}`, keys.encKey);
    const check = token
      ? await verifyToken({ secret, token, lastStep: 0, toleranceSeconds: config.toleranceSeconds })
      : { valid: false, step: null };

    if (!check.valid || check.step === null) {
      const exceeded = registerPendingFailure(req);
      return fail(res, 400, exceeded ? 'Muitas tentativas inválidas. Reinicie a troca.' : 'Código inválido.');
    }

    const { plain, hashes } = newRecoveryCodeSet(config.recoveryCodeCount, keys.macKey);
    store.transaction(() => {
      // O segredo antigo e TODOS os códigos de recuperação anteriores deixam de valer.
      store.upsertTotp(pending.userId, encryptSecret(secret, `totp:${pending.userId}`, keys.encKey), check.step!);
      store.replaceRecoveryCodes(pending.userId, hashes);
      store.addEvent(pending.userId, 'rotate', 'autenticador substituído');
    });
    clearPending(req);
    req.session.authMethod = 'totp';
    res.json({ recoveryCodes: plain });
  });

  return router;
}
