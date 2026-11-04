import type { Request } from 'express';
import type { UserVerification } from './webauthn.js';

const CHALLENGE_TTL_MS = 5 * 60 * 1000; // 5 minutos

export type ChallengePurpose = 'registration' | 'authentication' | 'step-up';

/**
 * Guarda o desafio da cerimônia na sessão do servidor, junto com a política de
 * verificação do usuário vigente. Assim, a verificação aplica exatamente a política
 * que foi solicitada ao autenticador, mesmo que ela mude entre as duas etapas.
 */
export function storeChallenge(
  req: Request,
  purpose: ChallengePurpose,
  value: string,
  userVerification: UserVerification,
  pendingUser?: { id: string; username: string },
): void {
  req.session.challenge = {
    value,
    purpose,
    userVerification,
    pendingUser,
    expiresAt: Date.now() + CHALLENGE_TTL_MS,
  };
}

/** Recupera e INVALIDA o desafio (uso único). Retorna null se ausente, expirado ou de outra finalidade. */
export function consumeChallenge(req: Request, purpose: ChallengePurpose) {
  const challenge = req.session.challenge;
  delete req.session.challenge;
  if (!challenge) return null;
  if (challenge.purpose !== purpose) return null;
  if (challenge.expiresAt < Date.now()) return null;
  return challenge;
}

/**
 * Inicia a sessão autenticada, regenerando o identificador (evita session fixation).
 * Se a autenticação incluiu verificação do usuário, registra o instante dela.
 */
export function loginSession(req: Request, userId: string, userVerified: boolean): Promise<void> {
  return new Promise((resolve, reject) => {
    req.session.regenerate((err) => {
      if (err) return reject(err);
      req.session.userId = userId;
      if (userVerified) req.session.uvAt = Date.now();
      req.session.save((saveErr) => (saveErr ? reject(saveErr) : resolve()));
    });
  });
}

export function logoutSession(req: Request): Promise<void> {
  return new Promise((resolve, reject) => {
    req.session.destroy((err) => (err ? reject(err) : resolve()));
  });
}
