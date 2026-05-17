// Node's fetch has no default timeout. Agents running inside cages talk
// to upstream targets through the payload-proxy, which intercepts TLS
// and forwards requests. On cold start (first request to a hostname),
// the proxy must generate a per-hostname cert from the cage CA — this
// can take a few seconds, especially when several requests run in
// parallel. A 30s default keeps cold-start scenarios reliable without
// hiding real outages.
const DEFAULT_TIMEOUT_MS = 30_000;

export interface FetchOptions extends RequestInit {
  /** Per-request timeout in milliseconds. Default: 30000. */
  timeoutMs?: number;
}

/**
 * fetch is a drop-in replacement for Node's global fetch with a
 * platform-aware default timeout. Agents should prefer this over the
 * global fetch so they get sensible behavior under the cage proxy
 * without each agent reinventing timeout handling.
 */
export async function fetch(url: string | URL, init: FetchOptions = {}): Promise<Response> {
  const { timeoutMs = DEFAULT_TIMEOUT_MS, signal, ...rest } = init;
  const timeoutSignal = AbortSignal.timeout(timeoutMs);
  // Compose with any caller-provided signal so external cancellation
  // still works alongside the timeout.
  const combined = signal ? AbortSignal.any([signal, timeoutSignal]) : timeoutSignal;
  return globalThis.fetch(url, { ...rest, signal: combined });
}
