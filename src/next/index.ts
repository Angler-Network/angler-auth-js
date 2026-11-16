import { AuthError } from "../errors.ts";
import { getSessionToken, SESSION_COOKIE } from "../server/session.ts";
import { createTokenVerifier } from "../server/verify.ts";
import type { AuthClaims } from "../types.ts";

export { AuthError, isAuthError } from "../errors.ts";
export type { AuthClaims } from "../types.ts";
export { TokenError } from "../server/verify.ts";

/** What `cookies()` of `next/headers` and `request.cookies` give: the cookies with their decoded values. */
export interface CookieStoreLike {
  getAll(): ReadonlyArray<{ name: string; value: string }>;
}

/** A `Cookie` header, or anything it can be read from. `cookies()` is async since Next 15: pass its promise as is. */
export type CookieSource =
  | string
  | null
  | undefined
  | Headers
  | { headers: Headers }
  | CookieStoreLike
  | Promise<string | null | undefined | Headers | { headers: Headers } | CookieStoreLike>;

export interface NextAuthOptions {
  /** The auth service, e.g. `https://auth.angler.network`; also the expected token issuer. */
  authUrl: string;
  /** Your app's own origin, one of the service's `ALLOWED_ORIGINS`. */
  origin: string;
  /** The service's `JWT_AUDIENCE`. Default `authenticated`. */
  audience?: string;
  /** Only for an http dev service, which names the cookie `angler_session`. */
  cookieName?: string;
  fetch?: typeof fetch;
  now?: () => number;
  /** Default 5000. */
  timeoutMs?: number;
}

export interface ProtectOptions {
  /** Where to send a visitor who is not signed in (your sign-in page; absolute, or relative to the request). Default: answer `401`. */
  redirectTo?: string;
}

export interface NextAuth {
  /** The user's access token, or `null` when nobody is signed in. Calls the service. */
  getToken(source: CookieSource): Promise<string | null>;
  /** The verified claims of the signed-in user, or `null`. Calls the service, then checks the token offline. */
  getClaims(source: CookieSource): Promise<AuthClaims | null>;
  /** Like `getClaims`; throws `AuthError` `unauthenticated` (401) when nobody is signed in. */
  requireClaims(source: CookieSource): Promise<AuthClaims>;
  /**
   * Whether the session cookie is there, and nothing more: the cookie is opaque and never trusted
   * without asking the service. Use it to skip work or to redirect early, never to let anyone in.
   */
  hasSessionCookie(source: CookieSource): Promise<boolean>;
  /**
   * For middleware (Edge runtime): `null` when the visitor is signed in, otherwise the `Response` to return
   * (a redirect to `redirectTo`, or `401`). Asks the service on every call, so match it to the paths that
   * need a user. An ML-DSA-65 token can't be verified on the Edge: use `JWT_ALG=EdDSA` there.
   */
  protect(request: Request, options?: ProtectOptions): Promise<Response | null>;
}

function isStore(value: object): value is CookieStoreLike {
  return typeof (value as CookieStoreLike).getAll === "function";
}

/** The `Cookie` header value to read the session cookie from. */
async function cookieHeaderOf(source: CookieSource, cookieName: string): Promise<string | null> {
  const resolved = await source;
  if (resolved === null || resolved === undefined || typeof resolved === "string") return resolved ?? null;
  if (isStore(resolved)) {
    // Every cookie of that name, so a planted duplicate still reaches the service.
    return resolved
      .getAll()
      .filter((cookie) => cookie.name === cookieName)
      .map((cookie) => `${cookie.name}=${encodeURIComponent(cookie.value)}`)
      .join("; ");
  }
  return ("headers" in resolved ? resolved.headers : resolved).get("cookie");
}

export function createNextAuth(options: NextAuthOptions): NextAuth {
  const cookieName = options.cookieName ?? SESSION_COOKIE;
  // One verifier for the life of the app: it keeps the JWKS cached between requests.
  const verifier = createTokenVerifier({
    issuer: options.authUrl.replace(/\/+$/, ""),
    ...(options.audience ? { audience: options.audience } : {}),
    ...(options.fetch ? { fetch: options.fetch } : {}),
    ...(options.now ? { now: options.now } : {}),
  });

  async function getToken(source: CookieSource): Promise<string | null> {
    return getSessionToken(await cookieHeaderOf(source, cookieName), {
      authUrl: options.authUrl,
      origin: options.origin,
      cookieName,
      ...(options.fetch ? { fetch: options.fetch } : {}),
      ...(options.timeoutMs ? { timeoutMs: options.timeoutMs } : {}),
    });
  }

  async function getClaims(source: CookieSource): Promise<AuthClaims | null> {
    const token = await getToken(source);
    return token ? verifier.tryVerify(token) : null;
  }

  return {
    getToken,
    getClaims,
    async requireClaims(source) {
      const claims = await getClaims(source);
      if (!claims) throw new AuthError({ status: 401, code: "unauthenticated" });
      return claims;
    },
    async hasSessionCookie(source) {
      const header = await cookieHeaderOf(source, cookieName);
      return (header ?? "").split(";").some((part) => part.trim().startsWith(`${cookieName}=`));
    },
    async protect(request, opts = {}) {
      if (await getClaims(request)) return null;
      if (opts.redirectTo) return Response.redirect(new URL(opts.redirectTo, request.url), 307);
      return Response.json({ error: "unauthenticated" }, { status: 401, headers: { "cache-control": "no-store" } });
    },
  };
}
