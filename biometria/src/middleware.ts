import type { NextFunction, Request, Response } from 'express';
import { fail } from './http.js';

/** Indica se a última verificação do usuário ocorreu dentro da janela de validade. */
export function isUvFresh(uvAt: number | undefined, windowMs: number, now = Date.now()): boolean {
  if (typeof uvAt !== 'number') return false;
  const age = now - uvAt;
  return age >= 0 && age <= windowMs;
}

export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  if (!req.session.userId) return fail(res, 401, 'Não autenticado.', 'AUTH_REQUIRED');
  next();
}

/**
 * Exige autenticação E verificação do usuário recente (step-up). Usado em ações
 * sensíveis: mesmo com a sessão aberta, o servidor pede nova confirmação biométrica
 * (ou PIN do dispositivo) quando a última verificação é antiga ou inexistente.
 */
export function requireFreshUv(windowMs: number) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.session.userId) return fail(res, 401, 'Não autenticado.', 'AUTH_REQUIRED');
    if (!isUvFresh(req.session.uvAt, windowMs)) {
      return fail(res, 403, 'Confirmação biométrica necessária para esta ação.', 'UV_REQUIRED');
    }
    next();
  };
}
