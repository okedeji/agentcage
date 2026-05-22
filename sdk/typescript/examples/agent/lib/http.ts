import { fetch } from '@agentcage/sdk';
import { authHeaders } from './auth';

export interface HttpResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

// FetchResult always carries the reason for failure when ok is false.
// The prior shape (HttpResponse | null) silently swallowed every error
// — connection refused, DNS failures, TLS errors, body-read aborts —
// which left tools reporting an opaque "response unavailable" with no
// way for the operator to tell what actually went wrong.
export type FetchResult =
  | { ok: true; response: HttpResponse }
  | { ok: false; error: string };

// fetchSafe wraps the SDK fetch (routes through the payload proxy)
// with auth-header injection and body truncation. Never throws; the
// caller inspects result.ok and reads either result.response or
// result.error.
export async function fetchSafe(
  url: string,
  extraHeaders: Record<string, string> = {},
): Promise<FetchResult> {
  try {
    const merged = { ...authHeaders(), ...extraHeaders };
    const resp = await fetch(url, { redirect: 'follow', headers: merged });
    const body = await resp.text();
    const headers: Record<string, string> = {};
    resp.headers.forEach((v, k) => {
      headers[k] = v;
    });
    return {
      ok: true,
      response: { status: resp.status, headers, body: body.slice(0, 8192) },
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { ok: false, error: msg };
  }
}
