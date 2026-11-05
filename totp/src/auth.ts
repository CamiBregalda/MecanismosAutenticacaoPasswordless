import type { Store } from './db.js';
import { decryptSecret, hashRecoveryCode, normalizeRecoveryCode } from './crypto.js';
import type { Keys } from './crypto.js';
import { applyFailure, isLocked } from './lockout.js';
import type { LockState } from './lockout.js';
import { verifyToken } from './totp.js';

export interface AuthDeps {
  store: Store;
  keys: Keys;
  toleranceSeconds: number;
}

/**
 * 'ok'      : credencial aceita
 * 'invalid' : credencial recusada (a falha foi contabilizada)
 * 'locked'  : conta bloqueada; a credencial NEM foi avaliada
 */
export type CheckResult = 'ok' | 'invalid' | 'locked';

/** Contabiliza uma falha, persiste o novo estado e registra os eventos. */
function registerFailure(deps: AuthDeps, userId: string, lock: LockState, now: number): CheckResult {
  const next = applyFailure(lock, now);
  deps.store.saveLockState(userId, next);
  deps.store.addEvent(userId, 'login_failed', `falhas consecutivas: ${next.failedAttempts}`);
  if (next.lockedUntil > now) {
    deps.store.addEvent(userId, 'locked', `bloqueio ${next.lockCount} até ${new Date(next.lockedUntil).toISOString()}`);
  }
  return 'invalid';
}

/** Verifica um código TOTP do usuário, com bloqueio, tolerância e proteção contra reutilização. */
export async function checkTotp(
  deps: AuthDeps,
  userId: string,
  token: string,
  now = Date.now(),
): Promise<CheckResult> {
  const record = deps.store.getTotp(userId);
  if (!record) return 'invalid';
  if (isLocked(record.lock, now)) {
    deps.store.addEvent(userId, 'login_failed', 'conta bloqueada');
    return 'locked';
  }

  const secret = decryptSecret(record.secretEnc, `totp:${userId}`, deps.keys.encKey);
  const check = await verifyToken({
    secret,
    token,
    lastStep: record.lastStep,
    toleranceSeconds: deps.toleranceSeconds,
    nowMs: now,
  });

  // A atualização condicional do passo impede que duas requisições simultâneas
  // com o mesmo código sejam ambas aceitas.
  if (check.valid && check.step !== null && deps.store.advanceLastStep(userId, check.step)) {
    deps.store.resetLock(userId);
    return 'ok';
  }
  return registerFailure(deps, userId, record.lock, now);
}

/** Verifica e CONSOME um código de recuperação (uso único). */
export function checkRecoveryCode(
  deps: AuthDeps,
  userId: string,
  input: unknown,
  now = Date.now(),
): CheckResult {
  const record = deps.store.getTotp(userId);
  if (!record) return 'invalid';
  if (isLocked(record.lock, now)) {
    deps.store.addEvent(userId, 'login_failed', 'conta bloqueada');
    return 'locked';
  }

  const code = normalizeRecoveryCode(input);
  if (code && deps.store.consumeRecoveryCode(userId, hashRecoveryCode(code, deps.keys.macKey))) {
    deps.store.resetLock(userId);
    return 'ok';
  }
  return registerFailure(deps, userId, record.lock, now);
}
