import { base64urlDecode, decodeJwtPart } from "../base64url.ts";
import type { AuthClaims, AuthMethod } from "../types.ts";

export type TokenErrorCode =
  | "malformed"
  | "unsupported_alg"
  | "unknown_key"
  | "key_mismatch"
  | "bad_signature"
  | "expired"
  | "not_yet_valid"
  | "bad_issuer"
  | "bad_audience"
  | "invalid_claims"
  /** The JWKS could not be fetched. Not the token's fault: retry, don't treat the user as signed out. */
  | "jwks_unavailable"
  /** An ML-DSA-65 token on a runtime without it. Set `JWT_ALG=EdDSA` on the service, or run Node 24.7+. */
  | "ml_dsa_unsupported";

export class TokenError extends Error {
  readonly code: TokenErrorCode;

  constructor(code: TokenErrorCode, message?: string, options?: { cause?: unknown }) {
    super(message ?? code, options);
    this.name = "TokenError";
    this.code = code;
  }
}

export type TokenAlgorithm = "EdDSA" | "ML-DSA-65";

interface Jwk {
  kty?: unknown;
  crv?: unknown;
  alg?: unknown;
  use?: unknown;
  kid: string;
  x?: unknown;
  pub?: unknown;
}

type NodeCrypto = Pick<typeof import("node:crypto"), "createPublicKey" | "generateKeyPairSync" | "verify">;

export interface VerifyOptions {
  /** The service's `AUTH_URL`, exactly as it is in the token's `iss`. */
  issuer: string;
  /** The service's `JWT_AUDIENCE`. Default `authenticated`. */
  audience?: string;
  /** Default `<issuer>/.well-known/jwks.json`. */
  jwksUrl?: string;
  fetch?: typeof fetch;
  /** Allowed difference between this clock and the service's, for `exp` and `nbf`. Default 5. */
  clockToleranceSeconds?: number;
  /** How long a JWKS is used before it is fetched again. Default 300, the service's own cache-control. */
  jwksCacheSeconds?: number;
  /** An unknown `kid` (a key just rotated in) fetches the JWKS again, but at most this often. Default 10. */
  jwksRefetchSeconds?: number;
  /** When the JWKS can't be fetched, a key already cached still verifies for this long past its expiry. Default 600. */
  jwksMaxStaleSeconds?: number;
  /** Milliseconds since the epoch. Defaults to `Date.now`. */
  now?: () => number;
  /**
   * Gives `node:crypto` (for ML-DSA-65, which WebCrypto doesn't have yet), or null when the runtime has none.
   * Defaults to a dynamic `import("node:crypto")`; only called when an ML-DSA-65 token arrives.
   */
  loadNodeCrypto?: () => Promise<NodeCrypto | null>;
}

export interface TokenVerifier {
  /** Resolves with the claims of a valid token and throws a `TokenError` otherwise. */
  verify(jwt: string): Promise<AuthClaims>;
  /** Like `verify`, but `null` for a token that is simply not valid. Still throws `jwks_unavailable` and `ml_dsa_unsupported`: the answer is unknown. */
  tryVerify(jwt: string): Promise<AuthClaims | null>;
}

const ALGORITHMS: readonly string[] = ["EdDSA", "ML-DSA-65"];

async function defaultLoadNodeCrypto(): Promise<NodeCrypto | null> {
  try {
    // Through a variable, so a bundler for the Edge runtime has no static import of a Node module to refuse.
    const specifier = "node:crypto";
    return (await import(/* webpackIgnore: true */ specifier)) as NodeCrypto;
  } catch {
    return null;
  }
}

interface KeySetOptions {
  url: string;
  fetch: typeof fetch;
  now: () => number;
  jwksCacheSeconds: number;
  jwksRefetchSeconds: number;
  jwksMaxStaleSeconds: number;
}

/** Keys of the service, with the fetch policy of the README: 5 minute cache, refetch on an unknown kid. */
class KeySet {
  #keys = new Map<string, Jwk>();
  #imported = new Map<string, Promise<unknown>>();
  #fetchedAt = 0;
  #attemptedAt = Number.NEGATIVE_INFINITY;
  #failed = false;
  #loading: Promise<void> | null = null;
  readonly #options: KeySetOptions;

  constructor(options: KeySetOptions) {
    this.#options = options;
  }

  async find(kid: string): Promise<Jwk | undefined> {
    const { now, jwksCacheSeconds, jwksRefetchSeconds } = this.#options;
    const hit = this.#keys.get(kid);
    if (hit && now() - this.#fetchedAt < jwksCacheSeconds * 1000) return hit;
    if (this.#loading || now() - this.#attemptedAt >= jwksRefetchSeconds * 1000) {
      try {
        await this.#refresh();
      } catch (error) {
        return this.#staleOrThrow(kid, error);
      }
      return this.#keys.get(kid);
    }
    // Looked a moment ago: a key that is still unknown is not coming, and one that failed is not retried yet.
    return this.#failed ? this.#staleOrThrow(kid, new TokenError("jwks_unavailable")) : hit;
  }

  /** The key as an imported, verification-ready object, built once per key. */
  imported<T>(jwk: Jwk, build: () => Promise<T>): Promise<T> {
    let entry = this.#imported.get(jwk.kid);
    if (!entry) {
      entry = build();
      this.#imported.set(jwk.kid, entry);
      // A failed import (malformed key) must not stick.
      entry.catch(() => this.#imported.delete(jwk.kid));
    }
    return entry as Promise<T>;
  }

  #staleOrThrow(kid: string, error: unknown): Jwk {
    const { now, jwksCacheSeconds, jwksMaxStaleSeconds } = this.#options;
    const hit = this.#keys.get(kid);
    if (hit && now() - this.#fetchedAt < (jwksCacheSeconds + jwksMaxStaleSeconds) * 1000) return hit;
    throw error instanceof TokenError ? error : new TokenError("jwks_unavailable", "could not fetch the JWKS", { cause: error });
  }

  #refresh(): Promise<void> {
    this.#loading ??= this.#fetchKeys().finally(() => {
      this.#loading = null;
    });
    return this.#loading;
  }

  async #fetchKeys(): Promise<void> {
    const { url, fetch: fetchImpl, now } = this.#options;
    this.#attemptedAt = now();
    try {
      const response = await fetchImpl(url, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(5000), cache: "no-store" });
      if (!response.ok) throw new Error(`JWKS answered ${response.status}`);
      const body: unknown = await response.json();
      const list = (body as { keys?: unknown } | null)?.keys;
      if (!Array.isArray(list)) throw new Error("JWKS has no keys");
      const keys = new Map<string, Jwk>();
      for (const item of list) {
        if (item && typeof item === "object" && typeof (item as Jwk).kid === "string") keys.set((item as Jwk).kid, item as Jwk);
      }
      // Replaced as a whole: a key the service dropped (revoked) stops verifying.
      this.#keys = keys;
      this.#imported.clear();
      this.#fetchedAt = now();
      this.#failed = false;
    } catch (cause) {
      this.#failed = true;
      throw new TokenError("jwks_unavailable", "could not fetch the JWKS", { cause });
    }
  }
}

/** Whether this `node:crypto` (OpenSSL 3.5, Node 24.7+) has ML-DSA-65. */
function mlDsaAvailable(crypto: NodeCrypto): boolean {
  try {
    crypto.generateKeyPairSync("ml-dsa-65" as "ed25519");
    return true;
  } catch {
    return false;
  }
}

export function createTokenVerifier(options: VerifyOptions): TokenVerifier {
  const now = options.now ?? Date.now;
  const audience = options.audience ?? "authenticated";
  const toleranceMs = (options.clockToleranceSeconds ?? 5) * 1000;
  const loadNodeCrypto = options.loadNodeCrypto ?? defaultLoadNodeCrypto;
  let mlDsaNode: Promise<NodeCrypto | null> | undefined;
  // Loaded and probed once, on the first ML-DSA-65 token.
  const nodeWithMlDsa = () =>
    (mlDsaNode ??= loadNodeCrypto().then((node) => (node && mlDsaAvailable(node) ? node : null)));
  const keys = new KeySet({
    url: options.jwksUrl ?? `${options.issuer.replace(/\/+$/, "")}/.well-known/jwks.json`,
    fetch: options.fetch ?? ((input, init) => globalThis.fetch(input, init)),
    now,
    jwksCacheSeconds: options.jwksCacheSeconds ?? 300,
    jwksRefetchSeconds: options.jwksRefetchSeconds ?? 10,
    jwksMaxStaleSeconds: options.jwksMaxStaleSeconds ?? 600,
  });

  async function signatureValid(jwk: Jwk, alg: string, data: Uint8Array<ArrayBuffer>, signature: Uint8Array<ArrayBuffer>): Promise<boolean> {
    if (alg === "EdDSA") {
      if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") throw new TokenError("key_mismatch");
      try {
        const key = await keys.imported(jwk, () =>
          globalThis.crypto.subtle.importKey("jwk", { kty: "OKP", crv: "Ed25519", x: jwk.x as string }, { name: "Ed25519" }, false, ["verify"]),
        );
        return await globalThis.crypto.subtle.verify({ name: "Ed25519" }, key, signature, data);
      } catch {
        return false;
      }
    }
    if (jwk.kty !== "AKP" || typeof jwk.pub !== "string") throw new TokenError("key_mismatch");
    const node = await nodeWithMlDsa();
    if (!node) {
      throw new TokenError("ml_dsa_unsupported", "ML-DSA-65 needs Node 24.7+; set JWT_ALG=EdDSA on the service to sign for other runtimes");
    }
    try {
      const key = await keys.imported(jwk, async () => node.createPublicKey({ key: { kty: "AKP", alg: "ML-DSA-65", pub: jwk.pub as string } as never, format: "jwk" }));
      return node.verify(null, data, key, signature);
    } catch {
      return false;
    }
  }

  async function verify(jwt: string): Promise<AuthClaims> {
    const parts = jwt.split(".");
    if (parts.length !== 3) throw new TokenError("malformed");
    const [h, p, s] = parts as [string, string, string];
    const header = decodeJwtPart(h);
    const payload = decodeJwtPart(p);
    if (!header || !payload) throw new TokenError("malformed");
    let signature: Uint8Array<ArrayBuffer>;
    try {
      signature = base64urlDecode(s);
    } catch {
      throw new TokenError("malformed");
    }
    // Only the algorithms the service signs with; never "none", never HS*. `crit` extensions are not understood.
    if (typeof header.alg !== "string" || !ALGORITHMS.includes(header.alg)) throw new TokenError("unsupported_alg", `alg ${String(header.alg)} is not accepted`);
    if (header.crit !== undefined) throw new TokenError("malformed", "crit header");
    if (typeof header.kid !== "string") throw new TokenError("unknown_key", "no kid");

    // The key is chosen by kid alone and then must be of the algorithm the header claims.
    const jwk = await keys.find(header.kid);
    if (!jwk) throw new TokenError("unknown_key", `no key ${header.kid}`);
    if (jwk.alg !== header.alg || (jwk.use !== undefined && jwk.use !== "sig")) throw new TokenError("key_mismatch");
    if (!(await signatureValid(jwk, header.alg, new TextEncoder().encode(`${h}.${p}`), signature))) throw new TokenError("bad_signature");

    const seconds = now() / 1000;
    const tolerance = toleranceMs / 1000;
    if (payload.iss !== options.issuer) throw new TokenError("bad_issuer");
    const aud = payload.aud;
    if (!(aud === audience || (Array.isArray(aud) && aud.includes(audience)))) throw new TokenError("bad_audience");
    if (typeof payload.sub !== "string" || payload.sub === "") throw new TokenError("invalid_claims", "no sub");
    if (typeof payload.exp !== "number" || !Number.isFinite(payload.exp)) throw new TokenError("invalid_claims", "no exp");
    if (payload.exp <= seconds - tolerance) throw new TokenError("expired");
    if (payload.nbf !== undefined && (typeof payload.nbf !== "number" || !Number.isFinite(payload.nbf))) throw new TokenError("invalid_claims", "bad nbf");
    if (typeof payload.nbf === "number" && payload.nbf > seconds + tolerance) throw new TokenError("not_yet_valid");
    return payload as AuthClaims;
  }

  return {
    verify,
    async tryVerify(jwt) {
      try {
        return await verify(jwt);
      } catch (error) {
        if (error instanceof TokenError && error.code !== "jwks_unavailable" && error.code !== "ml_dsa_unsupported") return null;
        throw error;
      }
    },
  };
}

const shared = new Map<string, TokenVerifier>();

function sharedVerifier(options: VerifyOptions): TokenVerifier {
  // Custom fetch, clock or crypto loader means a test or a special runtime: no cache shared across calls.
  if (options.fetch || options.now || options.loadNodeCrypto) return createTokenVerifier(options);
  const key = JSON.stringify([options.issuer, options.audience, options.jwksUrl, options.clockToleranceSeconds, options.jwksCacheSeconds, options.jwksRefetchSeconds, options.jwksMaxStaleSeconds]);
  let verifier = shared.get(key);
  if (!verifier) {
    verifier = createTokenVerifier(options);
    shared.set(key, verifier);
  }
  return verifier;
}

/**
 * Verifies an access token offline against the service's JWKS: signature (EdDSA or ML-DSA-65), `iss`,
 * `aud`, `exp` and `nbf`. The JWKS is cached in the process and fetched again when a new key id shows up.
 * Throws a `TokenError`.
 */
export function verifyToken(jwt: string, options: VerifyOptions): Promise<AuthClaims> {
  return sharedVerifier(options).verify(jwt);
}

/**
 * Like `verifyToken`, but resolves with `null` for a token that is simply not valid (expired, forged,
 * wrong audience). Still throws when the answer is unknown: `jwks_unavailable` and `ml_dsa_unsupported`.
 */
export function tryVerifyToken(jwt: string, options: VerifyOptions): Promise<AuthClaims | null> {
  return sharedVerifier(options).tryVerify(jwt);
}

/** The audience of a step-up proof. An access token has another one, so neither passes as the other. */
export const STEP_UP_AUDIENCE = "step-up";

/** Claims of a step-up proof (`proof` from `stepUp` or `stepUpWithPasskey` with an `action`). */
export interface StepUpClaims {
  iss: string;
  aud: string;
  role: "step_up";
  sub: string;
  /** First 32 characters of the session id, as in that session's access tokens. */
  sid: string;
  action: string;
  /** The factor the person used for this proof. */
  amr: AuthMethod[];
  auth_time: number;
  /** The app origin that asked for the proof. */
  origin: string | null;
  jti: string;
  iat: number;
  exp: number;
}

export interface StepUpExpectation {
  /** The signed-in user the change is for. */
  userId: string;
  /** The change about to be made, exactly as the browser sent it to `stepUp`. */
  action: string;
  /** This app's origin. */
  origin: string;
  /** The session the request comes from (`sid` of its access token): a proof made in another session is refused. */
  sessionId: string;
  /** Oldest accepted proof, in seconds. Default 300 (the service's own limit). */
  maxAgeSeconds?: number;
}

/**
 * Verifies a step-up proof before one sensitive change: the signature, `iss`, `exp`, audience `step-up`, and that
 * the proof is for this user, session, action and app, made in the last five minutes. Throws a `TokenError`.
 *
 * It does not remember proofs: store `jti` (for example with a unique index) and refuse one seen before, so a proof
 * makes one change only.
 */
export async function verifyStepUpProof(
  proof: string,
  expected: StepUpExpectation,
  options: Omit<VerifyOptions, "audience">,
): Promise<StepUpClaims> {
  const claims = (await sharedVerifier({ ...options, audience: STEP_UP_AUDIENCE }).verify(proof)) as unknown as StepUpClaims;
  const tolerance = options.clockToleranceSeconds ?? 5;
  const maxAge = expected.maxAgeSeconds ?? 300;
  const seconds = (options.now ?? Date.now)() / 1000;
  if (!expected.userId || !expected.action || !expected.origin || !expected.sessionId) {
    throw new TypeError("verifyStepUpProof needs userId, sessionId, action and origin");
  }
  if (claims.role !== "step_up") throw new TokenError("invalid_claims", "not a step-up proof");
  if (claims.sub !== expected.userId) throw new TokenError("invalid_claims", "proof is for another user");
  if (claims.sid !== expected.sessionId) throw new TokenError("invalid_claims", "proof is from another session");
  if (claims.action !== expected.action) throw new TokenError("invalid_claims", "proof is for another action");
  if (claims.origin !== expected.origin) throw new TokenError("invalid_claims", "proof was asked for by another app");
  if (typeof claims.jti !== "string" || claims.jti === "") throw new TokenError("invalid_claims", "no jti");
  if (typeof claims.auth_time !== "number" || claims.auth_time < seconds - maxAge - tolerance) {
    throw new TokenError("expired", "proof is too old");
  }
  return claims;
}
