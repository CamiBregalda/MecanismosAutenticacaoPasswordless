import { config } from './config.js';
import type { UserVerification } from './webauthn.js';

// Política vigente no servidor. É fixa, salvo em modo laboratório (LAB_MODE=1).
let current: UserVerification = config.userVerification;

export function getPolicy(): UserVerification {
  return current;
}

export function setPolicy(policy: UserVerification): void {
  current = policy;
}
