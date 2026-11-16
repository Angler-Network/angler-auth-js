import { AuthError } from "../errors.ts";
import { joinUrl, requestJson } from "../http.ts";

/** The shared session cookie angler-auth sets on `COOKIE_DOMAIN` when it is served over https. */
export const SESSION_COOKIE = "__Secure-angler_session";

export interface SessionTokenOptions {
  /** The auth service, e.g. `https://auth.angler.network`. */
  authUrl: string;
  /** Your app's own origin, one of the service's `ALLOWED_ORIGINS`. `POST /token` is refused (`invalid_origin`) without it. */
  origin: string;
  fetch?: typeof fetch;
  /** Only for an http dev service, which names the cookie `angler_session`. */
  cookieName?: string;
  /** Default 5000. */
  timeoutMs?: number;
}

/**
 * The session cookie pairs of a `Cookie` header, exactly as sent. A name that appears twice is
 * forwarded twice: the service reads that as a planted cookie and answers signed out.
 */
export function sessionCookiePairs(cookieHeader: string | null | undefined, cookieName: string = SESSION_COOKIE): string[] {
  if (!cookieHeader) return [];
  const pairs: string[] = [];
  for (const part of cookieHeader.split(";")) {
    const pair = part.trim();
    const index = pair.indexOf("=");
    if (index > 0 && pair.slice(0, index) === cookieName) pairs.push(pair);
  }
  return pairs;
}

/**
 * Asks angler-auth who the request's cookie belongs to and returns that user's access token (a JWT,
 * 10 minutes by default), or `null` when nobody is signed in. Only the session cookie is forwarded.
 * Verify the token with `verifyToken` and keep it on the server.
 *
 * Throws an `AuthError` when the service can't answer (`rate_limited`, a 5xx, no connection).
 */
export async function getSessionToken(cookieHeader: string | null | undefined, options: SessionTokenOptions): Promise<string | null> {
  const pairs = sessionCookiePairs(cookieHeader, options.cookieName);
  if (pairs.length === 0) return null;
  try {
    const { token } = await requestJson<{ token?: unknown }>(options.fetch ?? ((input, init) => globalThis.fetch(input, init)), joinUrl(options.authUrl, "/token"), {
      method: "POST",
      headers: { cookie: pairs.join("; "), origin: new URL(options.origin).origin },
      signal: AbortSignal.timeout(options.timeoutMs ?? 5000),
      cache: "no-store",
    });
    if (typeof token !== "string") throw new AuthError({ status: 200, code: "invalid_response" });
    return token;
  } catch (error) {
    // Not signed in, or signed in but still owing the second factor: no token for either.
    if (error instanceof AuthError && (error.code === "unauthenticated" || error.code === "mfa_required")) return null;
    throw error;
  }
}
