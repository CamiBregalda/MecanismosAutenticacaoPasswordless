import 'express-session';

declare module 'express-session' {
  interface SessionData {
    /** Identificador do usuário autenticado. */
    userId?: string;
    /** Desafio de uma cerimônia WebAuthn em andamento (uso único). */
    challenge?: {
      value: string;
      purpose: 'registration' | 'authentication';
      pendingUser?: { id: string; username: string };
      expiresAt: number;
    };
  }
}
