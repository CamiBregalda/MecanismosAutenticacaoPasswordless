const USERNAME_PATTERN = /^[a-z0-9._@-]{3,64}$/;

/** Normaliza e valida o nome de usuário. Retorna null se for inválido. */
export function normalizeUsername(input: unknown): string | null {
  if (typeof input !== 'string') return null;
  const normalized = input.trim().toLowerCase();
  return USERNAME_PATTERN.test(normalized) ? normalized : null;
}
