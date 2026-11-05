import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  hkdfSync,
  randomBytes,
} from 'node:crypto';

/** Chaves derivadas da chave mestra, uma para cada finalidade. */
export interface Keys {
  /** Cifragem dos segredos TOTP (AES-256-GCM). */
  encKey: Buffer;
  /** Autenticação (HMAC) dos códigos de recuperação. */
  macKey: Buffer;
}

/**
 * Deriva subchaves independentes a partir da chave mestra (HKDF-SHA-256).
 * Usar chaves distintas por finalidade evita que o comprometimento de um uso
 * afete o outro.
 */
export function deriveKeys(appKey: string): Keys {
  const ikm = Buffer.from(appKey, 'utf8');
  const salt = Buffer.from('guia-totp-v1', 'utf8');
  return {
    encKey: Buffer.from(hkdfSync('sha256', ikm, salt, 'enc:totp-secret', 32)),
    macKey: Buffer.from(hkdfSync('sha256', ikm, salt, 'mac:recovery-code', 32)),
  };
}

// ---------------------------------------------------------------------------
// Cifragem do segredo TOTP
// ---------------------------------------------------------------------------

const VERSION = 'v1';
const IV_BYTES = 12;
const TAG_BYTES = 16;

/**
 * Cifra o segredo com AES-256-GCM. O formato é "v1.<base64url(iv|tag|texto cifrado)>".
 * O parâmetro `aad` (dados autenticados adicionais) vincula o texto cifrado ao seu
 * contexto (por exemplo, o usuário): copiar o valor para outra linha do banco faz a
 * decifragem falhar. O prefixo de versão permite trocar o esquema no futuro.
 */
export function encryptSecret(plaintext: string, aad: string, key: Buffer): string {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${VERSION}.${Buffer.concat([iv, tag, encrypted]).toString('base64url')}`;
}

/** Decifra e AUTENTICA. Lança exceção se o conteúdo, a chave ou o contexto forem alterados. */
export function decryptSecret(token: string, aad: string, key: Buffer): string {
  const [version, payload] = token.split('.');
  if (version !== VERSION || !payload) throw new Error('Formato de segredo cifrado inválido.');
  const raw = Buffer.from(payload, 'base64url');
  if (raw.length <= IV_BYTES + TAG_BYTES) throw new Error('Segredo cifrado truncado.');
  const iv = raw.subarray(0, IV_BYTES);
  const tag = raw.subarray(IV_BYTES, IV_BYTES + TAG_BYTES);
  const encrypted = raw.subarray(IV_BYTES + TAG_BYTES);
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAAD(Buffer.from(aad, 'utf8'));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

// ---------------------------------------------------------------------------
// Códigos de recuperação
// ---------------------------------------------------------------------------

// Alfabeto de 32 símbolos (Crockford): sem I, L, O e U, para evitar confusão visual.
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const CODE_LENGTH = 10; // 10 símbolos x 5 bits = 50 bits de entropia

/** Gera um código aleatório no formato XXXXX-XXXXX. */
export function generateRecoveryCode(): string {
  const bytes = randomBytes(CODE_LENGTH);
  let code = '';
  for (const byte of bytes) {
    // 256 é múltiplo de 32: o mapeamento por máscara não introduz viés.
    code += ALPHABET[byte & 31];
  }
  return `${code.slice(0, 5)}-${code.slice(5)}`;
}

/** Gera `count` códigos distintos. */
export function generateRecoveryCodes(count: number): string[] {
  const codes = new Set<string>();
  while (codes.size < count) codes.add(generateRecoveryCode());
  return [...codes];
}

/**
 * Normaliza a entrada do usuário: ignora maiúsculas, espaços e hífens e aplica as
 * equivalências de Crockford (O→0, I/L→1). Retorna o código canônico de 10 símbolos
 * ou null se o formato for inválido.
 */
export function normalizeRecoveryCode(input: unknown): string | null {
  if (typeof input !== 'string') return null;
  const canonical = input
    .toUpperCase()
    .replace(/[\s-]/g, '')
    .replace(/O/g, '0')
    .replace(/[IL]/g, '1');
  return /^[0-9A-HJKMNP-TV-Z]{10}$/.test(canonical) ? canonical : null;
}

/**
 * Calcula o HMAC-SHA-256 do código canônico com a chave do servidor. O banco guarda
 * apenas esse valor: o código em texto claro é exibido uma única vez ao usuário.
 */
export function hashRecoveryCode(canonicalCode: string, macKey: Buffer): string {
  return createHmac('sha256', macKey).update(canonicalCode).digest('hex');
}

/**
 * Gera um conjunto de códigos: o texto claro (exibido ao usuário uma única vez) e os
 * HMACs correspondentes (o que de fato é gravado no banco).
 */
export function newRecoveryCodeSet(count: number, macKey: Buffer): { plain: string[]; hashes: string[] } {
  const plain = generateRecoveryCodes(count);
  const hashes = plain.map((code) => hashRecoveryCode(normalizeRecoveryCode(code)!, macKey));
  return { plain, hashes };
}
