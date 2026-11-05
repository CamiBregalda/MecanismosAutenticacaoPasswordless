/**
 * Limitador de janela fixa, em memória, por chave (por exemplo, endereço IP).
 * Complementa o bloqueio por conta: contém tentativas distribuídas entre muitos
 * nomes de usuário. Em produção com várias instâncias, use um armazenamento compartilhado.
 */
export class RateLimiter {
  private hits = new Map<string, { count: number; resetAt: number }>();
  private max: number;
  private windowMs: number;

  constructor(max: number, windowMs: number) {
    this.max = max;
    this.windowMs = windowMs;
  }

  /** Registra uma tentativa. Retorna true se ainda está dentro do limite. */
  take(key: string, now = Date.now()): boolean {
    if (this.hits.size > 10_000) this.prune(now);
    const entry = this.hits.get(key);
    if (!entry || entry.resetAt <= now) {
      this.hits.set(key, { count: 1, resetAt: now + this.windowMs });
      return true;
    }
    entry.count += 1;
    return entry.count <= this.max;
  }

  private prune(now: number): void {
    for (const [key, entry] of this.hits) {
      if (entry.resetAt <= now) this.hits.delete(key);
    }
  }
}
