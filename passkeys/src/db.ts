import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

export interface User {
  id: string; // user handle (base64url, 32 bytes aleatórios)
  username: string;
  createdAt: string;
}

export interface StoredCredential {
  id: string; // credential ID (base64url)
  userId: string;
  publicKey: Uint8Array; // chave pública no formato COSE
  counter: number;
  transports: string[];
  deviceType: 'singleDevice' | 'multiDevice';
  backedUp: boolean;
  createdAt: string;
  lastUsedAt: string | null;
}

export type NewCredential = Omit<StoredCredential, 'createdAt' | 'lastUsedAt'>;

type Row = Record<string, unknown>;

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS users (
    id         TEXT PRIMARY KEY,
    username   TEXT NOT NULL UNIQUE COLLATE NOCASE,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS credentials (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_key   BLOB NOT NULL,
    counter      INTEGER NOT NULL DEFAULT 0,
    transports   TEXT NOT NULL DEFAULT '[]',
    device_type  TEXT NOT NULL,
    backed_up    INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    last_used_at TEXT
  );

  CREATE INDEX IF NOT EXISTS idx_credentials_user ON credentials(user_id);
`;

function toUser(row: Row): User {
  return {
    id: row.id as string,
    username: row.username as string,
    createdAt: row.created_at as string,
  };
}

function toCredential(row: Row): StoredCredential {
  return {
    id: row.id as string,
    userId: row.user_id as string,
    publicKey: new Uint8Array(row.public_key as Uint8Array),
    counter: Number(row.counter),
    transports: JSON.parse(row.transports as string) as string[],
    deviceType: row.device_type as StoredCredential['deviceType'],
    backedUp: Number(row.backed_up) === 1,
    createdAt: row.created_at as string,
    lastUsedAt: (row.last_used_at as string | null) ?? null,
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

  addCredential(c: NewCredential): void {
    this.db
      .prepare(
        `INSERT INTO credentials
           (id, user_id, public_key, counter, transports, device_type, backed_up)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        c.id,
        c.userId,
        c.publicKey,
        c.counter,
        JSON.stringify(c.transports),
        c.deviceType,
        c.backedUp ? 1 : 0,
      );
  }

  getCredentialById(id: string): StoredCredential | undefined {
    const row = this.db.prepare('SELECT * FROM credentials WHERE id = ?').get(id) as
      | Row
      | undefined;
    return row ? toCredential(row) : undefined;
  }

  listCredentials(userId: string): StoredCredential[] {
    const rows = this.db
      .prepare('SELECT * FROM credentials WHERE user_id = ? ORDER BY created_at, id')
      .all(userId) as Row[];
    return rows.map(toCredential);
  }

  updateCredentialUsage(id: string, counter: number, backedUp: boolean): void {
    this.db
      .prepare(
        `UPDATE credentials
            SET counter = ?, backed_up = ?, last_used_at = datetime('now')
          WHERE id = ?`,
      )
      .run(counter, backedUp ? 1 : 0, id);
  }

  deleteCredential(id: string, userId: string): boolean {
    const result = this.db
      .prepare('DELETE FROM credentials WHERE id = ? AND user_id = ?')
      .run(id, userId);
    return Number(result.changes) > 0;
  }
}
