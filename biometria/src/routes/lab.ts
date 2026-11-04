import { Router } from 'express';
import { config } from '../config.js';
import { fail } from '../http.js';
import { getPolicy, setPolicy } from '../policy.js';
import { parseUserVerification } from '../webauthn.js';

export function labRouter(): Router {
  const router = Router();

  // Informações públicas de configuração, usadas pela interface.
  router.get('/config', (_req, res) => {
    res.json({
      userVerification: getPolicy(),
      labMode: config.labMode,
      stepUpWindowSeconds: Math.round(config.stepUpWindowMs / 1000),
    });
  });

  // Alteração da política em tempo de execução: SOMENTE em modo laboratório.
  // Em produção, a política é decisão do servidor e nunca do cliente.
  router.post('/lab/policy', (req, res) => {
    if (!config.labMode) return fail(res, 404, 'Não encontrado.');
    try {
      setPolicy(parseUserVerification(req.body?.userVerification));
    } catch {
      return fail(res, 400, 'Política inválida.');
    }
    res.json({ userVerification: getPolicy() });
  });

  return router;
}
