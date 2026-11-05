import { generateSecret, verify } from 'otplib';

/**
 * Parâmetros do TOTP. São os valores padrão do RFC 6238 e os únicos aceitos de forma
 * confiável por todos os aplicativos autenticadores (alguns ignoram valores diferentes).
 */
export const TOTP_PARAMS = { algorithm: 'SHA1', digits: 6, period: 30 } as const;

/** Gera um segredo aleatório (CSPRNG), em Base32 sem preenchimento. A otplib usa 20 bytes (160 bits). */
export function newSecret(): string {
  return generateSecret();
}

/**
 * Monta a URI "otpauth://" lida pelos aplicativos autenticadores (formato "Key URI").
 * Os parâmetros são explicitados mesmo quando coincidem com os padrões.
 * ATENÇÃO: a URI contém o segredo. Nunca a envie a serviços externos de geração de QR Code.
 */
export function buildOtpauthUri(opts: { issuer: string; account: string; secret: string }): string {
  const issuer = encodeURIComponent(opts.issuer);
  const label = `${issuer}:${encodeURIComponent(opts.account)}`;
  const { algorithm, digits, period } = TOTP_PARAMS;
  return `otpauth://totp/${label}?secret=${opts.secret}&issuer=${issuer}&algorithm=${algorithm}&digits=${digits}&period=${period}`;
}

/** Remove espaços e hifens digitados pelo usuário (ex.: "123 456"). */
export function normalizeToken(input: unknown): string | null {
  if (typeof input !== 'string') return null;
  const token = input.replace(/[\s-]/g, '');
  return token.length > 0 ? token : null;
}

export interface TokenCheck {
  valid: boolean;
  /** Passo de tempo (time step) em que o código foi aceito; null se inválido. */
  step: number | null;
}

/**
 * Verifica um código TOTP com:
 *  - tolerância de relógio (em segundos);
 *  - proteção contra reutilização: rejeita passos de tempo <= `lastStep`
 *    (RFC 6238, seção 5.2: o verificador não deve aceitar o mesmo código duas vezes).
 *
 * Falha de forma segura: qualquer entrada malformada ou erro da biblioteca resulta em
 * "inválido". Na versão 13 da otplib, tokens malformados LANÇAM exceção (na v12 retornavam false).
 */
export async function verifyToken(args: {
  secret: string;
  token: string;
  lastStep: number;
  toleranceSeconds: number;
  nowMs?: number;
}): Promise<TokenCheck> {
  const invalid: TokenCheck = { valid: false, step: null };
  if (!/^\d{6}$/.test(args.token)) return invalid;

  try {
    // Forma mínima do resultado que a aplicação consome.
    const result = (await verify({
      secret: args.secret,
      token: args.token,
      epochTolerance: args.toleranceSeconds,
      afterTimeStep: args.lastStep,
      ...(args.nowMs === undefined ? {} : { epoch: Math.floor(args.nowMs / 1000) }),
    })) as unknown as { valid: boolean; timeStep?: number };

    if (result.valid && typeof result.timeStep === 'number' && result.timeStep > args.lastStep) {
      return { valid: true, step: result.timeStep };
    }
    return invalid;
  } catch (error) {
    // Não registra o código nem o segredo, apenas o tipo do erro.
    console.warn('[totp] erro na verificação:', (error as Error).name);
    return invalid;
  }
}
