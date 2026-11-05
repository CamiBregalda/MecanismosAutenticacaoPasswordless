/** Estado de bloqueio de uma conta por tentativas consecutivas inválidas. */
export interface LockState {
  /** Falhas consecutivas desde o último bloqueio ou sucesso. */
  failedAttempts: number;
  /** Quantos bloqueios já ocorreram desde o último sucesso (escalonamento). */
  lockCount: number;
  /** Instante (ms) até o qual a conta permanece bloqueada. */
  lockedUntil: number;
}

export const MAX_FAILURES = 5;
const BASE_LOCK_MS = 15 * 60 * 1000; // 15 minutos
const MAX_LOCK_MS = 24 * 60 * 60 * 1000; // 24 horas

export const INITIAL_LOCK_STATE: LockState = { failedAttempts: 0, lockCount: 0, lockedUntil: 0 };

export function isLocked(state: LockState, now: number): boolean {
  return state.lockedUntil > now;
}

/** Duração do n-ésimo bloqueio: 15 min, 30 min, 1 h, 2 h... limitada a 24 h. */
export function lockDurationMs(lockCount: number): number {
  return Math.min(BASE_LOCK_MS * 2 ** Math.max(0, lockCount - 1), MAX_LOCK_MS);
}

/** Aplica uma falha. Ao atingir o limite, inicia um bloqueio cada vez mais longo. */
export function applyFailure(state: LockState, now: number): LockState {
  const failedAttempts = state.failedAttempts + 1;
  if (failedAttempts < MAX_FAILURES) return { ...state, failedAttempts };
  const lockCount = state.lockCount + 1;
  return { failedAttempts: 0, lockCount, lockedUntil: now + lockDurationMs(lockCount) };
}
