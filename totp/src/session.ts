import type { Request } from 'express';

const PENDING_TTL_MS = 10 * 60 * 1000; // 10 minutos para escanear o QR e confirmar
const MAX_PENDING_ATTEMPTS = 5;

type Pending = NonNullable<Request['session']['pendingEnrollment']>;
export type AuthMethod = NonNullable<Request['session']['authMethod']>;

/** Inicia um cadastro (ou troca) pendente, com o segredo já cifrado. */
export function startPending(
  req: Request,
  pending: Omit<Pending, 'attempts' | 'expiresAt'>,
): void {
  req.session.pendingEnrollment = {
    ...pending,
    attempts: 0,
    expiresAt: Date.now() + PENDING_TTL_MS,
  };
}

/** Retorna o cadastro pendente do tipo pedido, se existir e não tiver expirado. */
export function getPending(req: Request, kind: Pending['kind']): Pending | null {
  const pending = req.session.pendingEnrollment;
  if (!pending || pending.kind !== kind) return null;
  if (pending.expiresAt < Date.now()) {
    delete req.session.pendingEnrollment;
    return null;
  }
  return pending;
}

/** Conta uma tentativa inválida. Retorna true se o limite foi atingido (e o pendente descartado). */
export function registerPendingFailure(req: Request): boolean {
  const pending = req.session.pendingEnrollment;
  if (!pending) return true;
  pending.attempts += 1;
  if (pending.attempts >= MAX_PENDING_ATTEMPTS) {
    delete req.session.pendingEnrollment;
    return true;
  }
  return false;
}

export function clearPending(req: Request): void {
  delete req.session.pendingEnrollment;
}

/** Inicia a sessão autenticada, regenerando o identificador (evita session fixation). */
export function loginSession(req: Request, userId: string, method: AuthMethod): Promise<void> {
  return new Promise((resolve, reject) => {
    req.session.regenerate((err) => {
      if (err) return reject(err);
      req.session.userId = userId;
      req.session.authAt = Date.now();
      req.session.authMethod = method;
      req.session.save((saveErr) => (saveErr ? reject(saveErr) : resolve()));
    });
  });
}

export function logoutSession(req: Request): Promise<void> {
  return new Promise((resolve, reject) => {
    req.session.destroy((err) => (err ? reject(err) : resolve()));
  });
}
