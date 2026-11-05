import express from 'express';
import type { NextFunction, Request, Response } from 'express';
import session from 'express-session';
import path from 'node:path';
import { config } from './config.js';
import { deriveKeys } from './crypto.js';
import { Store } from './db.js';
import { rateLimit } from './middleware.js';
import { RateLimiter } from './rateLimit.js';
import { accountRouter } from './routes/account.js';
import { enrollRouter } from './routes/enroll.js';
import { loginRouter } from './routes/login.js';

const root = path.resolve(import.meta.dirname, '..');

if (config.usingDevKey) {
  console.warn('[aviso] APP_KEY não definida: usando chave de desenvolvimento (INSEGURA). Defina APP_KEY no .env.');
}

const store = new Store(config.dbPath);
const keys = deriveKeys(config.appKey);
const limiter = rateLimit(new RateLimiter(config.rateLimit.max, config.rateLimit.windowMs));
const deps = { store, keys, toleranceSeconds: config.toleranceSeconds };

const app = express();
app.disable('x-powered-by');
if (config.trustProxy) app.set('trust proxy', 1);

// "img-src data:" é necessário apenas para exibir o QR Code (gerado localmente).
app.use((_req, res, next) => {
  res.setHeader('Content-Security-Policy', "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'");
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  // Respostas com segredos e códigos de recuperação não devem ser armazenadas em cache.
  res.setHeader('Cache-Control', 'no-store');
  next();
});

app.use(express.json({ limit: '100kb' }));

// ATENÇÃO: o armazenamento de sessão padrão (memória) serve apenas para demonstração.
app.use(
  session({
    name: 'sid',
    secret: config.sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: config.secureCookies,
      maxAge: 8 * 60 * 60 * 1000,
    },
  }),
);

app.use('/api/enroll', enrollRouter({ store, keys, limiter }));
app.use('/api/login', loginRouter(deps, limiter));
app.use('/api', accountRouter(deps, limiter));

app.use(express.static(path.join(root, 'public')));

app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error('[erro]', err);
  res.status(500).json({ error: 'Erro interno do servidor.' });
});

app.listen(config.port, () => {
  console.log(`Servidor em ${config.origin} (tolerância: ±${config.toleranceSeconds} s)`);
});
