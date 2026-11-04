export type UserVerification = 'required' | 'preferred' | 'discouraged';

/** Valida um valor externo (variável de ambiente ou corpo de requisição). */
export function parseUserVerification(value: unknown): UserVerification {
  if (value === 'required' || value === 'preferred' || value === 'discouraged') {
    return value;
  }
  throw new Error(
    `Política de verificação inválida: "${String(value)}". Use required, preferred ou discouraged.`,
  );
}

/**
 * Define se o SERVIDOR rejeita respostas cujo flag UV (user verified) seja falso.
 *
 * Atenção: pedir `userVerification: "required"` na geração das opções NÃO basta.
 * Essa opção é apenas um pedido ao navegador e ao autenticador; quem garante a
 * política é a verificação, no servidor, do flag UV assinado pelo autenticador.
 * Por isso a política é aplicada nos dois momentos (opções e verificação).
 */
export function requiresUserVerification(policy: UserVerification): boolean {
  return policy === 'required';
}

/** Algoritmos de chave pública aceitos (COSE): -8 EdDSA, -7 ES256, -257 RS256. */
export const SUPPORTED_ALGORITHM_IDS = [-8, -7, -257];
