import { parseUserVerification } from './webauthn.js';

const origin = new URL(process.env.ORIGIN ?? 'http://localhost:3000');
const isProduction = process.env.NODE_ENV === 'production';

if (isProduction && !process.env.SESSION_SECRET) {
  throw new Error('Defina SESSION_SECRET em produção.');
}
if (isProduction && process.env.LAB_MODE === '1') {
  throw new Error('LAB_MODE=1 não pode ser usado em produção.');
}

const stepUpWindowSeconds = Number(process.env.STEP_UP_WINDOW_SECONDS ?? 300);
if (!Number.isFinite(stepUpWindowSeconds) || stepUpWindowSeconds <= 0) {
  throw new Error('STEP_UP_WINDOW_SECONDS deve ser um número positivo.');
}

export const config = {
  port: Number(process.env.PORT ?? 3000),
  rpName: process.env.RP_NAME ?? 'Guia de Biometria (TCC)',
  rpID: process.env.RP_ID || origin.hostname,
  origin: origin.origin,
  // Política inicial. Em modo laboratório, pode ser alterada em tempo de execução (policy.ts).
  userVerification: parseUserVerification(process.env.USER_VERIFICATION ?? 'required'),
  stepUpWindowMs: stepUpWindowSeconds * 1000,
  labMode: process.env.LAB_MODE === '1',
  sessionSecret: process.env.SESSION_SECRET || 'segredo-apenas-para-desenvolvimento',
  dbPath: process.env.DB_PATH ?? './data/biometria.db',
  secureCookies: origin.protocol === 'https:',
  trustProxy: process.env.TRUST_PROXY === '1',
} as const;
