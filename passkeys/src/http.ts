import type { Response } from 'express';

/**
 * Envia uma resposta de erro JSON e devolve `void`.
 *
 * Os tipos do Express 5 declaram que um handler devolve `void | Promise<void>`.
 * Por isso os handlers não podem fazer `return res.status(...).json(...)`, que
 * devolveria o objeto `Response`. Com este utilitário, o padrão
 * `if (condição) return fail(res, 400, 'mensagem');` é aceito pelo compilador.
 */
export function fail(res: Response, status: number, error: string, code?: string): void {
  res.status(status).json(code ? { error, code } : { error });
}
