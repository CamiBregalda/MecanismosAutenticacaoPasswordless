const origin = new URL(process.env.ORIGIN ?? 'http://localhost:3000');
const isProduction = process.env.NODE_ENV === 'production';

const DEV_APP_KEY = 'chave-apenas-para-desenvolvimento-nao-use-em-producao';

if (isProduction) {
  if (!process.env.SESSION_SECRET) throw new Error('Defina SESSION_SECRET em produção.');
  if (!process.env.APP_KEY || process.env.APP_KEY.length < 32) {
    throw new Error('Defina APP_KEY em produção, com ao menos 32 caracteres.');
  }
}

const toleranceSeconds = Number(process.env.TOTP_TOLERANCE_SECONDS ?? 30);
if (!Number.isFinite(toleranceSeconds) || toleranceSeconds < 0 || toleranceSeconds > 90) {
  throw new Error('TOTP_TOLERANCE_SECONDS deve estar entre 0 e 90.');
}

export const config = {
  port: Number(process.env.PORT ?? 3000),
  origin: origin.origin,
  issuer: process.env.TOTP_ISSUER ?? 'Guia TOTP (TCC)',
  toleranceSeconds,
  recoveryCodeCount: 10,
  appKey: process.env.APP_KEY || DEV_APP_KEY,
  usingDevKey: !process.env.APP_KEY,
  sessionSecret: process.env.SESSION_SECRET || 'segredo-apenas-para-desenvolvimento',
  dbPath: process.env.DB_PATH ?? './data/totp.db',
  secureCookies: origin.protocol === 'https:',
  trustProxy: process.env.TRUST_PROXY === '1',
  // Limite de requisições de autenticação por endereço IP.
  rateLimit: { max: 30, windowMs: 15 * 60 * 1000 },
  // Tempo máximo desde o login para operações de troca de autenticador.
  recentLoginMs: 10 * 60 * 1000,
} as const;
