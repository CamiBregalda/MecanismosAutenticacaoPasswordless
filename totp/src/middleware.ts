import type { NextFunction, Request, Response } from 'express';
import { fail } from './http.js';
import type { RateLimiter } from './rateLimit.js';

export function isRecent(authAt: number | undefined, maxAgeMs: number, now = Date.now()): boolean {
  if (typeof authAt !== 'number') return false;
  const age = now - authAt;
  return age >= 0 && age <= maxAgeMs;
}

export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  if (!req.session.userId) return fail(res, 401, 'Não autenticado.', 'AUTH_REQUIRED');
  next();
}

/** Exige que o login tenha ocorrido há pouco tempo (operações sensíveis, como trocar o autenticador). */
export function requireRecentLogin(maxAgeMs: number) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.session.userId) return fail(res, 401, 'Não autenticado.', 'AUTH_REQUIRED');
    if (!isRecent(req.session.authAt, maxAgeMs)) {
      return fail(res, 403, 'Faça login novamente para realizar esta operação.', 'RECENT_LOGIN_REQUIRED');
    }
    next();
  };
}

/** Limita as requisições por endereço IP. */
export function rateLimit(limiter: RateLimiter) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const key = req.ip ?? 'desconhecido';
    if (!limiter.take(key)) {
      return fail(res, 429, 'Muitas requisições. Tente novamente mais tarde.', 'RATE_LIMITED');
    }
    next();
  };
}
