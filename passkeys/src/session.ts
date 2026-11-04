import type { Request } from 'express';

const CHALLENGE_TTL_MS = 5 * 60 * 1000; // 5 minutos

export type ChallengePurpose = 'registration' | 'authentication';

/** Guarda o desafio da cerimônia na sessão do servidor. */
export function storeChallenge(
  req: Request,
  purpose: ChallengePurpose,
  value: string,
  pendingUser?: { id: string; username: string },
): void {
  req.session.challenge = {
    value,
    purpose,
    pendingUser,
    expiresAt: Date.now() + CHALLENGE_TTL_MS,
  };
}

/**
 * Recupera e INVALIDA o desafio (uso único). Retorna null se ausente,
 * expirado ou emitido para outra finalidade.
 */
export function consumeChallenge(req: Request, purpose: ChallengePurpose) {
  const challenge = req.session.challenge;
  delete req.session.challenge;
  if (!challenge) return null;
  if (challenge.purpose !== purpose) return null;
  if (challenge.expiresAt < Date.now()) return null;
  return challenge;
}

/** Inicia a sessão autenticada, regenerando o identificador (evita session fixation). */
export function loginSession(req: Request, userId: string): Promise<void> {
  return new Promise((resolve, reject) => {
    req.session.regenerate((err) => {
      if (err) return reject(err);
      req.session.userId = userId;
      req.session.save((saveErr) => (saveErr ? reject(saveErr) : resolve()));
    });
  });
}

export function logoutSession(req: Request): Promise<void> {
  return new Promise((resolve, reject) => {
    req.session.destroy((err) => (err ? reject(err) : resolve()));
  });
}
