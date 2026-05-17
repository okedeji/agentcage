import { randomBytes } from 'crypto';

// 10 hex chars (40 bits) of entropy. ~1 in a billion collision risk per
// billion findings, far more than any agent will ever produce.
function generate(prefix: string): string {
  return prefix + randomBytes(5).toString('hex');
}

/** newFindingId returns a typed short ID like "fnd_b7d4e2a8c1". */
export function newFindingId(): string {
  return generate('fnd_');
}
