import QRCode from 'qrcode';

/**
 * Gera o QR Code localmente, como imagem em data URL. A URI otpauth contém o segredo,
 * por isso a geração NUNCA deve ser delegada a serviços externos.
 */
export function qrDataUrl(text: string): Promise<string> {
  return QRCode.toDataURL(text, { errorCorrectionLevel: 'M', margin: 2, width: 240 });
}
