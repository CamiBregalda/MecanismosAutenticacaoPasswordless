# Autenticação sem senha — guias e implementações de referência

Material prático do TCC *Investigação de Protocolos de Passwordless Authentication: uma proposta de guia* (UTFPR, Dois Vizinhos).

| Guia | Texto | Código | Situação |
|---|---|---|---|
| 1. Chaves criptográficas e passkeys | [docs/01-guia-passkeys.md](docs/01-guia-passkeys.md) | [passkeys/](passkeys/) | Disponível |
| 2. Biometria local | [docs/02-guia-biometria.md](docs/02-guia-biometria.md) | [biometria/](biometria/) | Disponível |
| 3. Tokens de software (TOTP) | [docs/03-guia-totp.md](docs/03-guia-totp.md) | [totp/](totp/) | Disponível |

## Stack comum

Node.js (LTS 22+), TypeScript, Express, SQLite. Bibliotecas: SimpleWebAuthn (passkeys e biometria) e otplib (TOTP).

