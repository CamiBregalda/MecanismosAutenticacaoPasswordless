# Tokens de software (TOTP) — implementação de referência

Aplicação de referência em **Node.js + TypeScript** de autenticação por **TOTP** (RFC 6238) com **códigos de recuperação** de uso único e **troca do autenticador**. Funciona com qualquer aplicativo autenticador que leia QR Code (Google Authenticator, Microsoft Authenticator, Aegis, Bitwarden, 1Password e outros).

Papel no trabalho: **contingência e recuperação de acesso**. O TOTP **não resiste a phishing em tempo real**; ele complementa, e não substitui, as passkeys.

O passo a passo completo, com a fundamentação teórica, está em [`../docs/03-guia-totp.md`](../docs/03-guia-totp.md).

## Requisitos

- Node.js **22.13 ou superior**
- Um aplicativo autenticador (opcional: sem celular, use `npm run code`)

## Início rápido

```bash
cd totp
cp .env.example .env      # preencha APP_KEY e SESSION_SECRET (ver abaixo)
npm install
npm run typecheck
npm test
npm run dev
```

Gere valores seguros para `APP_KEY` e `SESSION_SECRET`:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

Acesse <http://localhost:3000>.

## Testar sem celular

```bash
npm run code -- <CHAVE_BASE32_EXIBIDA_NO_CADASTRO>
npm run code -- <CHAVE> --offset=30     # simula relógio adiantado (+30 s)
```

## Variáveis de ambiente

| Variável | Padrão | Descrição |
|---|---|---|
| `ORIGIN` | `http://localhost:3000` | Origem acessada pelo navegador |
| `TOTP_ISSUER` | `Guia TOTP (TCC)` | Emissor exibido no aplicativo autenticador |
| `TOTP_TOLERANCE_SECONDS` | `30` | Tolerância de relógio em **segundos** (30 = passo anterior e seguinte) |
| `APP_KEY` | (apenas dev) | Chave mestra; **obrigatória em produção** (≥ 32 caracteres). Se for perdida, os segredos cadastrados deixam de ser legíveis |
| `SESSION_SECRET` | (apenas dev) | **Obrigatória** em produção |
| `DB_PATH` | `./data/totp.db` | Arquivo SQLite |
| `TRUST_PROXY` | `0` | `1` quando houver proxy/túnel HTTPS |

## Docker (opcional)

```bash
npm install            # gera o package-lock.json, exigido pelo Dockerfile
docker compose up --build   # exige APP_KEY e SESSION_SECRET no .env
```

## Aviso

Implementação **didática**. Leia a seção 8 do guia antes de qualquer uso em produção (gestão da `APP_KEY`, sessões persistentes, limitador compartilhado, bloqueio como vetor de negação de serviço, entre outros).
