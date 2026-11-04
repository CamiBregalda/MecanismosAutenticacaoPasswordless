# Passkeys (WebAuthn/FIDO2) — implementação de referência

Aplicação de referência em **Node.js + TypeScript** para autenticação com passkeys: registro, login (com ou sem nome de usuário), listagem e remoção de passkeys.

O passo a passo completo, com a fundamentação teórica, está em [`../docs/01-guia-passkeys.md`](../docs/01-guia-passkeys.md).

## Requisitos

- Node.js **22.13 ou superior**
- Um navegador atual (Chrome ou Edge recomendados para o autenticador virtual)

Não é necessário hardware dedicado nem conta em serviço de nuvem.

## Início rápido

```bash
cd passkeys
cp .env.example .env
npm install
npm test
npm run dev
```

Acesse <http://localhost:3000>. Para testar sem biometria real, use o autenticador virtual do Chrome DevTools (guia, seção 6.2).

## Variáveis de ambiente

| Variável | Padrão | Descrição |
|---|---|---|
| `ORIGIN` | `http://localhost:3000` | Origem completa acessada pelo navegador |
| `RP_ID` | domínio de `ORIGIN` | Domínio ao qual as credenciais ficam vinculadas (sem esquema e porta) |
| `USER_VERIFICATION` | `preferred` | `required`, `preferred` ou `discouraged` |
| `SESSION_SECRET` | (apenas dev) | **Obrigatória** quando `NODE_ENV=production` |
| `DB_PATH` | `./data/passkeys.db` | Arquivo SQLite |
| `TRUST_PROXY` | `0` | `1` quando houver proxy/túnel HTTPS |

## Docker (opcional)

```bash
npm install            # gera o package-lock.json, exigido pelo Dockerfile
echo "SESSION_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")" >> .env
docker compose up --build
```

## Aviso

Implementação **didática**. Antes de usar em produção, leia a seção 8 do guia (sessões persistentes, limitação de tentativas, recuperação de acesso, etc.). A compatibilidade com chaves de segurança físicas não foi validada em hardware.
