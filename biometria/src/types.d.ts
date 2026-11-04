import 'express-session';
import type { UserVerification } from './webauthn.js';

declare module 'express-session' {
  interface SessionData {
    /** Identificador do usuário autenticado. */
    userId?: string;
    /** Instante (ms) da última verificação do usuário (UV) bem-sucedida nesta sessão. */
    uvAt?: number;
    /** Desafio de uma cerimônia WebAuthn em andamento (uso único). */
    challenge?: {
      value: string;
      purpose: 'registration' | 'authentication' | 'step-up';
      /** Política vigente quando o desafio foi emitido; é a mesma aplicada na verificação. */
      userVerification: UserVerification;
      pendingUser?: { id: string; username: string };
      expiresAt: number;
    };
  }
}
