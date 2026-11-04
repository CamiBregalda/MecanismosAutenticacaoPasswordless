export type UserVerification = 'required' | 'preferred' | 'discouraged';

function parseUserVerification(value: string): UserVerification {
  if (value === 'required' || value === 'preferred' || value === 'discouraged') {
    return value;
  }
  throw new Error(
    `USER_VERIFICATION inválido: "${value}". Use required, preferred ou discouraged.`,
  );
}

const origin = new URL(process.env.ORIGIN ?? 'http://localhost:3000');
const isProduction = process.env.NODE_ENV === 'production';

if (isProduction && !process.env.SESSION_SECRET) {
  throw new Error('Defina SESSION_SECRET em produção.');
}

export const config = {
  port: Number(process.env.PORT ?? 3000),
  rpName: process.env.RP_NAME ?? 'Guia de Passkeys (TCC)',
  // O RP ID é o domínio ao qual a credencial fica vinculada (sem esquema e sem porta).
  rpID: process.env.RP_ID || origin.hostname,
  // A origem esperada é comparada com a origem declarada pelo navegador na cerimônia.
  origin: origin.origin,
  userVerification: parseUserVerification(process.env.USER_VERIFICATION ?? 'preferred'),
  sessionSecret: process.env.SESSION_SECRET || 'segredo-apenas-para-desenvolvimento',
  dbPath: process.env.DB_PATH ?? './data/passkeys.db',
  secureCookies: origin.protocol === 'https:',
  trustProxy: process.env.TRUST_PROXY === '1',
} as const;
