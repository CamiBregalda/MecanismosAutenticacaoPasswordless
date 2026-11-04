# Biometria local (WebAuthn com verificação do usuário) — implementação de referência

Aplicação de referência em **Node.js + TypeScript** que utiliza a biometria **local** do dispositivo (ou o PIN) como gesto de verificação do usuário no WebAuthn. O servidor nunca recebe dado biométrico: recebe uma assinatura e o resultado booleano da verificação (UV).

Funcionalidades: cadastro de dispositivo (autenticador de plataforma), login com política de verificação configurável (`required`, `preferred`, `discouraged`), confirmação de ações sensíveis (*step-up*) com janela de validade e trilha de eventos com o resultado de UV.

O passo a passo completo, com a fundamentação teórica, está em [`../docs/02-guia-biometria.md`](../docs/02-guia-biometria.md).

## Requisitos

- Node.js **22.13 ou superior**
- Navegador atual (Chrome ou Edge recomendados para o autenticador virtual)

Sensor biométrico **não é necessário**: o autenticador virtual do navegador reproduz os cenários (guia, seção 6.2).

## Início rápido

```bash
cd biometria
cp .env.example .env
npm install
npm run typecheck
npm test
npm run dev
```

Acesse <http://localhost:3000>. Para alternar a política pela interface, defina `LAB_MODE=1` no `.env`.

## Variáveis de ambiente

| Variável | Padrão | Descrição |
|---|---|---|
| `ORIGIN` | `http://localhost:3000` | Origem completa acessada pelo navegador |
| `RP_ID` | domínio de `ORIGIN` | Domínio das credenciais (sem esquema e porta) |
| `USER_VERIFICATION` | `required` | `required`, `preferred` ou `discouraged` |
| `STEP_UP_WINDOW_SECONDS` | `300` | Validade de uma verificação recente |
| `LAB_MODE` | `0` | `1` permite alterar a política pela interface (**proibido em produção**) |
| `SESSION_SECRET` | (apenas dev) | **Obrigatória** quando `NODE_ENV=production` |
| `DB_PATH` | `./data/biometria.db` | Arquivo SQLite |
| `TRUST_PROXY` | `0` | `1` quando houver proxy/túnel HTTPS |

## Docker (opcional)

```bash
npm install            # gera o package-lock.json, exigido pelo Dockerfile
echo "SESSION_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")" >> .env
docker compose up --build
```

## Aviso

Implementação **didática**. O servidor não consegue distinguir biometria de PIN: o flag UV indica apenas que o autenticador verificou o usuário por um método local. Leia a seção 8 do guia antes de qualquer uso em produção.
