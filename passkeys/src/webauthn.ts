/**
 * Algoritmos de chave pública aceitos (identificadores COSE):
 *   -8   = EdDSA
 *   -7   = ES256 (ECDSA com P-256 e SHA-256)
 *   -257 = RS256 (RSASSA-PKCS1-v1_5 com SHA-256)
 *
 * Na versão 14 do SimpleWebAuthn, a lista padrão passou a depender do runtime
 * (algoritmos pós-quânticos podem ser preferidos quando disponíveis). Fixar a
 * lista torna o comportamento independente da versão do Node.js utilizada e é
 * usado tanto na geração das opções quanto na verificação da resposta.
 */
export const SUPPORTED_ALGORITHM_IDS = [-8, -7, -257];
