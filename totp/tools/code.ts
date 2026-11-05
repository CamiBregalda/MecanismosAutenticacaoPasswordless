import { generate } from 'otplib';

/**
 * Ferramenta de APOIO AOS TESTES: calcula o código TOTP de um segredo Base32,
 * como faria um aplicativo autenticador. Permite testar sem celular e simular
 * desvio de relógio com --offset (em segundos).
 *
 * Uso:
 *   npm run code -- <SEGREDO_BASE32>
 *   npm run code -- <SEGREDO_BASE32> --offset=-30   (código do passo anterior)
 *   npm run code -- <SEGREDO_BASE32> --offset=-60   (fora da tolerância padrão)
 */
const args = process.argv.slice(2);
const secret = args.find((arg) => !arg.startsWith('--'))?.replace(/\s+/g, '').toUpperCase();
const offsetArg = args.find((arg) => arg.startsWith('--offset='));
const offset = offsetArg ? Number(offsetArg.split('=')[1]) : 0;

if (!secret || !Number.isFinite(offset)) {
  console.error('Uso: npm run code -- <SEGREDO_BASE32> [--offset=-30]');
  process.exit(1);
}

const now = Math.floor(Date.now() / 1000);
const token = await generate({ secret, epoch: now + offset });
const remaining = 30 - (now % 30);
const note = offset ? `; calculado com deslocamento de ${offset} s` : '';
console.log(`Código: ${token}  (o passo atual termina em ${remaining} s${note})`);
