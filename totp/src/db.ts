import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import type { LockState } from './lockout.js';

export interface User {
  id: string;
  username: string;
  createdAt: string;
}

export interface TotpRecord {
  userId: string;
  /** Segredo TOTP cifrado (AES-256-GCM). */
  secretEnc: string;
  /** Último passo de tempo aceito (proteção contra reutilização). */
  lastStep: number;
  lock: LockState;
  enrolledAt: string;
}

export type EventType =
  | 'enroll'
  | 'login_totp'
  | 'login_recovery'
  | 'login_failed'
  | 'locked'
  | 'rotate'
  | 'recovery_regenerated';

export interface AuthEvent {
  id: number;
  type: EventType;
  detail: string | null;
  createdAt: string;
}

type Row = Record<string, unknown>;

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS users (
    id         TEXT PRIMARY KEY,
    username   TEXT NOT NULL UNIQUE COLLATE NOCASE,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS totp (
    user_id         TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret_enc      TEXT NOT NULL,
    last_step       INTEGER NOT NULL DEFAULT 0,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    lock_count      INTEGER NOT NULL DEFAULT 0,
    locked_until    INTEGER NOT NULL DEFAULT 0,
    enrolled_at     TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS recovery_codes (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at   TEXT,
    UNIQUE (user_id, code_hash)
  );

  CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type       TEXT NOT NULL,
    detail     TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS idx_events_user ON events(user_id, id);
`;

function toUser(row: Row): User {
  return {
    id: row.id as string,
    username: row.username as string,
    createdAt: row.created_at as string,
  };
}

function toTotp(row: Row): TotpRecord {
  return {
    userId: row.user_id as string,
    secretEnc: row.secret_enc as string,
    lastStep: Number(row.last_step),
    lock: {
      failedAttempts: Number(row.failed_attempts),
      lockCount: Number(row.lock_count),
      lockedUntil: Number(row.locked_until),
    },
    enrolledAt: row.enrolled_at as string,
  };
}

export class Store {
  private db: DatabaseSync;

  constructor(path: string) {
    if (path !== ':memory:') {
      mkdirSync(dirname(path), { recursive: true });
    }
    this.db = new DatabaseSync(path);
    this.db.exec('PRAGMA foreign_keys = ON');
    this.db.exec(SCHEMA);
  }

  /** Executa `fn` de forma atômica: confirma se terminar, desfaz se lançar exceção. Não aninhável. */
  transaction<T>(fn: () => T): T {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const result = fn();
      this.db.exec('COMMIT');
      return result;
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  // --- usuários -----------------------------------------------------------

  createUser(id: string, username: string): User {
    this.db.prepare('INSERT INTO users (id, username) VALUES (?, ?)').run(id, username);
    return this.getUserById(id)!;
  }

  getUserById(id: string): User | undefined {
    const row = this.db.prepare('SELECT * FROM users WHERE id = ?').get(id) as Row | undefined;
    return row ? toUser(row) : undefined;
  }

  getUserByUsername(username: string): User | undefined {
    const row = this.db
      .prepare('SELECT * FROM users WHERE username = ?')
      .get(username) as Row | undefined;
    return row ? toUser(row) : undefined;
  }

  // --- segredo TOTP ---------------------------------------------------------

  /** Cria ou SUBSTITUI o segredo do usuário (troca de autenticador) e zera o bloqueio. */
  upsertTotp(userId: string, secretEnc: string, lastStep: number): void {
    this.db
      .prepare(
        `INSERT INTO totp (user_id, secret_enc, last_step)
         VALUES (?, ?, ?)
         ON CONFLICT (user_id) DO UPDATE SET
           secret_enc = excluded.secret_enc,
           last_step = excluded.last_step,
           failed_attempts = 0, lock_count = 0, locked_until = 0,
           enrolled_at = datetime('now')`,
      )
      .run(userId, secretEnc, lastStep);
  }

  getTotp(userId: string): TotpRecord | undefined {
    const row = this.db.prepare('SELECT * FROM totp WHERE user_id = ?').get(userId) as
      | Row
      | undefined;
    return row ? toTotp(row) : undefined;
  }

  /**
   * Avança o último passo aceito de forma ATÔMICA: só atualiza se `step` for maior que o
   * valor atual. Se duas requisições com o mesmo código chegarem ao mesmo tempo, apenas uma
   * obtém `true`. Isso fecha a condição de corrida da proteção contra reutilização.
   */
  advanceLastStep(userId: string, step: number): boolean {
    const result = this.db
      .prepare('UPDATE totp SET last_step = ? WHERE user_id = ? AND last_step < ?')
      .run(step, userId, step);
    return Number(result.changes) > 0;
  }

  saveLockState(userId: string, lock: LockState): void {
    this.db
      .prepare(
        'UPDATE totp SET failed_attempts = ?, lock_count = ?, locked_until = ? WHERE user_id = ?',
      )
      .run(lock.failedAttempts, lock.lockCount, lock.lockedUntil, userId);
  }

  resetLock(userId: string): void {
    this.saveLockState(userId, { failedAttempts: 0, lockCount: 0, lockedUntil: 0 });
  }

  // --- códigos de recuperação -------------------------------------------------

  /** Substitui TODOS os códigos do usuário (os anteriores deixam de valer). Chamar dentro de `transaction`. */
  replaceRecoveryCodes(userId: string, hashes: string[]): void {
    this.db.prepare('DELETE FROM recovery_codes WHERE user_id = ?').run(userId);
    const insert = this.db.prepare('INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)');
    for (const hash of hashes) insert.run(userId, hash);
  }

  /** Consome um código de forma atômica: retorna true apenas na primeira utilização. */
  consumeRecoveryCode(userId: string, hash: string): boolean {
    const result = this.db
      .prepare(
        `UPDATE recovery_codes SET used_at = datetime('now')
          WHERE user_id = ? AND code_hash = ? AND used_at IS NULL`,
      )
      .run(userId, hash);
    return Number(result.changes) > 0;
  }

  countUnusedRecoveryCodes(userId: string): number {
    const row = this.db
      .prepare('SELECT COUNT(*) AS n FROM recovery_codes WHERE user_id = ? AND used_at IS NULL')
      .get(userId) as Row;
    return Number(row.n);
  }

  // --- eventos ------------------------------------------------------------------

  addEvent(userId: string, type: EventType, detail: string | null = null): void {
    this.db
      .prepare('INSERT INTO events (user_id, type, detail) VALUES (?, ?, ?)')
      .run(userId, type, detail);
  }

  /** Eventos mais recentes primeiro. */
  listEvents(userId: string, limit = 20): AuthEvent[] {
    const rows = this.db
      .prepare('SELECT * FROM events WHERE user_id = ? ORDER BY id DESC LIMIT ?')
      .all(userId, limit) as Row[];
    return rows.map((row) => ({
      id: Number(row.id),
      type: row.type as EventType,
      detail: (row.detail as string | null) ?? null,
      createdAt: row.created_at as string,
    }));
  }
}
