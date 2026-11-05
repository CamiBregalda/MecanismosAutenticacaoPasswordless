import 'express-session';

declare module 'express-session' {
  interface SessionData {
    /** Identificador do usuário autenticado. */
    userId?: string;
    /** Instante (ms) em que a sessão foi autenticada. */
    authAt?: number;
    /** Método do login: indica, por exemplo, se o usuário entrou com código de recuperação. */
    authMethod?: 'enrollment' | 'totp' | 'recovery';
    /** Cadastro ou troca de autenticador em andamento (ainda não confirmado). */
    pendingEnrollment?: {
      kind: 'new' | 'rotate';
      userId: string;
      username: string;
      /** Segredo pendente, SEMPRE cifrado: nunca fica em texto claro no armazenamento da sessão. */
      secretEnc: string;
      attempts: number;
      expiresAt: number;
    };
  }
}
