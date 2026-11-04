import express from 'express';
import type { NextFunction, Request, Response } from 'express';
import session from 'express-session';
import path from 'node:path';
import { config } from './config.js';
import { Store } from './db.js';
import { accountRouter } from './routes/account.js';
import { actionsRouter } from './routes/actions.js';
import { authenticationRouter } from './routes/authentication.js';
import { labRouter } from './routes/lab.js';
import { registrationRouter } from './routes/registration.js';
import { stepUpRouter } from './routes/stepup.js';

const root = path.resolve(import.meta.dirname, '..');

const store = new Store(config.dbPath);
const app = express();

app.disable('x-powered-by');
if (config.trustProxy) app.set('trust proxy', 1);

app.use((_req, res, next) => {
  res.setHeader('Content-Security-Policy', "default-src 'self'; frame-ancestors 'none'");
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
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

app.use('/api/register', registrationRouter(store));
app.use('/api/login', authenticationRouter(store));
app.use('/api/step-up', stepUpRouter(store));
app.use('/api/actions', actionsRouter(store));
app.use('/api', labRouter());
app.use('/api', accountRouter(store));

app.use('/vendor', express.static(path.join(root, 'node_modules/@simplewebauthn/browser/dist/bundle')));
app.use(express.static(path.join(root, 'public')));

app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error('[erro]', err);
  res.status(500).json({ error: 'Erro interno do servidor.' });
});

app.listen(config.port, () => {
  console.log(
    `Servidor em ${config.origin} (RP ID: ${config.rpID}, UV: ${config.userVerification}, laboratório: ${config.labMode ? 'sim' : 'não'})`,
  );
});
