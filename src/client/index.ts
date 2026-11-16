import { decodeJwtPart } from "../base64url.ts";
import { AuthError } from "../errors.ts";
import { joinUrl, requestJson } from "../http.ts";
import type { AccountInfo, AuthMethod, Language, OAuthProvider } from "../types.ts";
import {
  assertionJson,
  creationOptions,
  credentialsContainer,
  prompt,
  registrationJson,
  requestOptions,
  type RegistrationOptionsJson,
  type RequestOptionsJson,
} from "./webauthn.ts";
import { buildSiweMessage, pageIdentity } from "./siwe.ts";

export { AuthError, isAuthError } from "../errors.ts";
export type { AuthErrorCode, AuthErrorInit } from "../errors.ts";
export type { AccountInfo, AuthClaims, AuthMethod, Language, OAuthProvider, WalletInfo } from "../types.ts";
export { buildSiweMessage, DEFAULT_SIWE_STATEMENT, type SiweMessageInput } from "./siwe.ts";

// --- types ------------------------------------------------------------------------------

export interface AuthClientOptions {
  /** The auth service, e.g. `https://auth.angler.network`. */
  baseUrl: string;
  /** Defaults to the global `fetch`. Every call is made with `credentials: "include"`. */
  fetch?: typeof fetch;
  /**
   * Gives the Cloudflare Turnstile token for the calls that need one (`captchaToken` of sign-up, sign-in,
   * forgot password, email code and magic link). A `captchaToken` passed to a call wins.
   */
  captcha?: () => string | Promise<string>;
  /** `getToken()` fetches a new token when the cached one has less than this left. Default 60. */
  refreshSkewSeconds?: number;
  /** Defaults to `navigator.credentials`. */
  credentials?: CredentialsContainer;
  /** Milliseconds since the epoch. Defaults to `Date.now`. */
  now?: () => number;
}

export interface CaptchaInput {
  captchaToken?: string;
}

/** `mfa_required`: the account has a second factor; finish with `verifyTotp`, `verifyRecoveryCode` or `verifyMfaWithPasskey`. */
export interface SignInResult {
  status: "signed_in" | "mfa_required";
  userId: string;
}

export interface MfaResult {
  status: "signed_in";
}

export type SessionInfo =
  | {
      status: "signed_in";
      user: AccountInfo;
      session: { id: string; methods: AuthMethod[]; expiresAt: string; authAt: string };
    }
  | { status: "mfa_required"; session: { methods: AuthMethod[] } };

export interface DeviceSession {
  id: string;
  current: boolean;
  methods: AuthMethod[];
  mfaPending: boolean;
  createdAt: string;
  lastSeenAt: string;
  ip: string | null;
  userAgent: string | null;
}

export interface PasskeyRegistered {
  status: "registered";
  id: string;
  postQuantum: boolean;
  /** Present for the account's first passkey: show them once. */
  recoveryCodes?: string[];
}

export interface EthereumSigner {
  /** EIP-55 checksummed or all-lowercase. */
  address: string;
  chainId: number;
  /** `personal_sign` of the message; a `0x` hex string. */
  signMessage: (message: string) => Promise<string>;
  /** Defaults to the page's `location.host` and `location.origin`; both must be allowed by the service. */
  domain?: string;
  uri?: string;
  statement?: string;
  /** Seconds the message stays valid. Default: the service's own limit (10 minutes). */
  expiresInSeconds?: number;
}

export interface ConfirmationCallback {
  /** Asked for the emailed code when the service says one was sent. Without it the call throws `confirmation_required`. */
  getConfirmationCode?: () => string | Promise<string>;
}

export interface AuthClient {
  // password
  /** Always answers `verification_sent`; finish with `verifyEmail`. */
  signUp(input: { email: string; password: string; name?: string; lang?: Language } & CaptchaInput): Promise<{ status: "verification_sent" }>;
  verifyEmail(input: { email: string; code: string }): Promise<SignInResult>;
  signIn(input: { email: string; password: string } & CaptchaInput): Promise<SignInResult>;
  /** Always answers `sent`. */
  forgotPassword(input: { email: string; lang?: Language } & CaptchaInput): Promise<{ status: "sent" }>;
  /** Signs in and ends every other session. */
  resetPassword(input: { email: string; code: string; password: string }): Promise<SignInResult>;
  /** Needs a sign-in from the last 15 minutes. */
  changePassword(input: { currentPassword?: string; newPassword: string }): Promise<{ status: "password_changed" }>;

  // passwordless
  requestEmailCode(input: { email: string; lang?: Language } & CaptchaInput): Promise<{ status: "sent" }>;
  /** Creates the account when the address is new. */
  verifyEmailCode(input: { email: string; code: string }): Promise<SignInResult>;
  /** The link only works in the browser that asked for it, and lands on `redirect` (an allowed origin). */
  requestMagicLink(input: { email: string; redirect?: string; lang?: Language } & CaptchaInput): Promise<{ status: "sent" }>;

  // OAuth
  /** The URL to navigate to (`location.assign`). OAuth is a redirect flow, not a fetch. */
  oauthUrl(provider: OAuthProvider, options?: { redirect?: string }): string;
  providers(): Promise<OAuthProvider[]>;
  /** `{ url }` to navigate to. Needs a recent sign-in. */
  linkOAuth(provider: OAuthProvider, options?: { redirect?: string }): Promise<{ url: string }>;
  unlinkOAuth(provider: OAuthProvider): Promise<{ status: "unlinked" }>;

  // wallets
  /** One-time nonce for an EIP-4361 message. */
  siweNonce(): Promise<{ nonce: string }>;
  /** Builds the message, has the caller sign it and verifies it. Creates the account when the wallet is new. */
  signInWithEthereum(signer: EthereumSigner): Promise<SignInResult>;
  /** Attaches the wallet to the signed-in account. Needs a recent sign-in. */
  linkEthereum(signer: EthereumSigner): Promise<{ status: "linked"; address: string }>;

  // passkeys
  registerPasskey(options?: { name?: string; lang?: Language } & ConfirmationCallback): Promise<PasskeyRegistered>;
  signInWithPasskey(options?: { mediation?: CredentialMediationRequirement; signal?: AbortSignal }): Promise<SignInResult>;
  removePasskey(id: string, options?: { lang?: Language } & ConfirmationCallback): Promise<{ status: "removed" }>;

  // second factor
  verifyTotp(code: string): Promise<MfaResult>;
  verifyRecoveryCode(recoveryCode: string): Promise<MfaResult>;
  verifyMfaWithPasskey(): Promise<MfaResult>;
  /** Starts enrolment: show `uri` as a QR code. */
  setupTotp(): Promise<{ secret: string; uri: string }>;
  /** Confirms enrolment with a first code; the recovery codes are shown once. */
  enableTotp(code: string): Promise<{ status: "enabled"; recoveryCodes: string[] }>;
  disableTotp(proof: { code: string } | { recoveryCode: string }): Promise<{ status: "disabled" }>;
  regenerateRecoveryCodes(code?: string): Promise<{ recoveryCodes: string[] }>;

  // session
  /** `null` when nobody is signed in. */
  getSession(): Promise<SessionInfo | null>;
  listSessions(): Promise<DeviceSession[]>;
  /** `id` is a session's `id` from `listSessions`. */
  revokeSession(id: string): Promise<{ status: "revoked" }>;
  revokeOtherSessions(): Promise<{ status: "revoked" }>;
  /** Ends this session; with `everywhere`, every other session first. */
  signOut(options?: { everywhere?: boolean }): Promise<void>;

  /**
   * A JWT for your servers and PostgREST (`Authorization: Bearer`). Cached in memory and renewed before it
   * expires; concurrent calls share one request. `null` when nobody is signed in (or the sign-in waits for
   * its second factor). Safe to pass as a callback: `accessToken: auth.getToken`.
   */
  getToken(options?: { forceRefresh?: boolean }): Promise<string | null>;
}

// --- helpers ------------------------------------------------------------------------------

/** What angler-auth put on the URL it sent the browser back to (`redirect` of OAuth and magic links). */
export function parseAuthReturn(url: string | URL): { authError: string | null; mfaRequired: boolean } {
  const params = new URL(url, "https://placeholder.invalid").searchParams;
  return { authError: params.get("auth_error"), mfaRequired: params.get("mfa") === "required" };
}

const DEFAULT_SKEW_SECONDS = 60;

interface CachedToken {
  token: string;
  refreshAt: number;
}

export function createAuthClient(options: AuthClientOptions): AuthClient {
  const baseUrl = options.baseUrl.replace(/\/+$/, "");
  const fetchImpl: typeof fetch = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
  const now = options.now ?? Date.now;
  const skewMs = (options.refreshSkewSeconds ?? DEFAULT_SKEW_SECONDS) * 1000;

  const call = <T>(method: "GET" | "POST", path: string, body?: unknown): Promise<T> =>
    requestJson<T>(fetchImpl, joinUrl(baseUrl, path), { method, body, credentials: "include" });
  const post = <T>(path: string, body?: unknown) => call<T>("POST", path, body);

  async function withCaptcha<T extends CaptchaInput>(input: T): Promise<Omit<T, "captchaToken"> & CaptchaInput> {
    const { captchaToken, ...rest } = input;
    const token = captchaToken ?? (await options.captcha?.());
    return token === undefined ? rest : { ...rest, captchaToken: token };
  }

  // --- access token cache ---
  let cached: CachedToken | null = null;
  let inflight: Promise<string | null> | null = null;
  let generation = 0;

  function clearToken(): void {
    cached = null;
    inflight = null;
    generation++;
  }

  function refreshAtFor(token: string, expiresAt: number, receivedAt: number): number {
    // Measure the lifetime on the token itself so a wrong clock on this device can't make the cache
    // useless (clock ahead) or serve an expired token (clock behind).
    const part = token.split(".")[1];
    const iat = (part ? decodeJwtPart(part) : null)?.iat;
    const lifetimeMs = typeof iat === "number" && expiresAt > iat ? (expiresAt - iat) * 1000 : expiresAt * 1000 - receivedAt;
    return receivedAt + lifetimeMs - skewMs;
  }

  async function fetchToken(): Promise<string | null> {
    const started = generation;
    let result: { token: string; expiresAt: number };
    try {
      result = await post<{ token: string; expiresAt: number }>("/token");
    } catch (error) {
      if (error instanceof AuthError && (error.code === "unauthenticated" || error.code === "mfa_required")) {
        if (started === generation) cached = null;
        return null;
      }
      throw error;
    }
    if (typeof result.token !== "string" || typeof result.expiresAt !== "number") {
      throw new AuthError({ status: 200, code: "invalid_response" });
    }
    // Signed in or out while this was in flight: the token belongs to the old session.
    if (started === generation) cached = { token: result.token, refreshAt: refreshAtFor(result.token, result.expiresAt, now()) };
    return result.token;
  }

  function getToken(opts: { forceRefresh?: boolean } = {}): Promise<string | null> {
    if (!opts.forceRefresh && cached && now() < cached.refreshAt) return Promise.resolve(cached.token);
    if (!inflight || opts.forceRefresh) {
      const request = fetchToken().finally(() => {
        if (inflight === request) inflight = null;
      });
      inflight = request;
    }
    return inflight;
  }

  /** A call that changes who is signed in or how: the cached token describes the old state. */
  async function changesSession<T>(run: () => Promise<T>): Promise<T> {
    try {
      return await run();
    } finally {
      clearToken();
    }
  }

  // --- WebAuthn ---
  async function confirmationCode(needed: boolean, callback: ConfirmationCallback): Promise<string | undefined> {
    if (!needed) return undefined;
    if (!callback.getConfirmationCode) throw new AuthError({ status: 0, code: "confirmation_required" });
    return callback.getConfirmationCode();
  }

  async function getAssertion(optionsPath: string, extra: { mediation?: CredentialMediationRequirement; signal?: AbortSignal } = {}) {
    const json = await post<RequestOptionsJson>(optionsPath);
    const container = credentialsContainer(options.credentials);
    const credential = await prompt(() =>
      container.get({
        publicKey: requestOptions(json),
        ...(extra.mediation ? { mediation: extra.mediation } : {}),
        ...(extra.signal ? { signal: extra.signal } : {}),
      }),
    );
    return assertionJson(credential);
  }

  // --- SIWE ---
  async function ethereum<T>(signer: EthereumSigner, link: boolean): Promise<T> {
    const domain = signer.domain ?? pageIdentity().domain;
    const uri = signer.uri ?? pageIdentity().uri;
    const { nonce } = await post<{ nonce: string }>("/wallet/nonce");
    const issued = new Date(now());
    const message = buildSiweMessage({
      domain,
      uri,
      address: signer.address,
      chainId: signer.chainId,
      nonce,
      issuedAt: issued.toISOString(),
      ...(signer.statement ? { statement: signer.statement } : {}),
      ...(signer.expiresInSeconds ? { expirationTime: new Date(issued.getTime() + signer.expiresInSeconds * 1000).toISOString() } : {}),
    });
    const signature = await signer.signMessage(message);
    return changesSession(() => post<T>("/wallet/verify", { message, signature, ...(link ? { link: true } : {}) }));
  }

  const oauthQuery = (redirect?: string) => (redirect ? `?redirect=${encodeURIComponent(redirect)}` : "");

  return {
    signUp: async (input) => post("/password/sign-up", await withCaptcha(input)),
    verifyEmail: (input) => changesSession(() => post("/password/verify-email", input)),
    signIn: async (input) => changesSession(async () => post("/password/sign-in", await withCaptcha(input))),
    forgotPassword: async (input) => post("/password/forgot", await withCaptcha(input)),
    resetPassword: (input) => changesSession(() => post("/password/reset", input)),
    changePassword: (input) => post("/password/change", input),

    requestEmailCode: async (input) => post("/email-code/send", await withCaptcha(input)),
    verifyEmailCode: (input) => changesSession(() => post("/email-code/verify", input)),
    requestMagicLink: async (input) => post("/magic-link/send", await withCaptcha(input)),

    oauthUrl: (provider, opts) => `${baseUrl}/oauth/${provider}${oauthQuery(opts?.redirect)}`,
    providers: async () => (await call<{ oauth: OAuthProvider[] }>("GET", "/providers")).oauth,
    linkOAuth: (provider, opts) => post(`/oauth/${provider}/link`, opts?.redirect ? { redirect: opts.redirect } : {}),
    unlinkOAuth: (provider) => post(`/oauth/${provider}/unlink`),

    siweNonce: () => post("/wallet/nonce"),
    signInWithEthereum: (signer) => ethereum<SignInResult>(signer, false),
    linkEthereum: (signer) => ethereum<{ status: "linked"; address: string }>(signer, true),

    async registerPasskey(opts = {}) {
      const json = await post<RegistrationOptionsJson>("/passkey/register/options", opts.lang ? { lang: opts.lang } : {});
      const container = credentialsContainer(options.credentials);
      const credential = await prompt(() => container.create({ publicKey: creationOptions(json) }));
      const code = await confirmationCode(json.confirmation === "email", opts);
      return post("/passkey/register/verify", {
        credential: registrationJson(credential),
        ...(code === undefined ? {} : { code }),
        ...(opts.name ? { name: opts.name } : {}),
      });
    },
    async signInWithPasskey(opts) {
      const credential = await getAssertion("/passkey/login/options", opts);
      return changesSession(() => post<SignInResult>("/passkey/login/verify", { credential }));
    },
    async removePasskey(id, opts = {}) {
      const { confirmation } = await post<{ confirmation: "email" | "none" }>("/passkey/remove/options", opts.lang ? { lang: opts.lang } : {});
      const code = await confirmationCode(confirmation === "email", opts);
      return post("/passkey/remove", { id, ...(code === undefined ? {} : { code }) });
    },

    verifyTotp: (code) => changesSession(() => post("/mfa/verify", { code })),
    verifyRecoveryCode: (recoveryCode) => changesSession(() => post("/mfa/verify", { recoveryCode })),
    async verifyMfaWithPasskey() {
      const credential = await getAssertion("/mfa/passkey/options");
      return changesSession(() => post<MfaResult>("/mfa/passkey/verify", { credential }));
    },
    setupTotp: () => post("/mfa/totp/setup"),
    enableTotp: (code) => post("/mfa/totp/enable", { code }),
    disableTotp: (proof) => post("/mfa/totp/disable", proof),
    regenerateRecoveryCodes: (code) => post("/mfa/recovery-codes", code === undefined ? {} : { code }),

    async getSession() {
      try {
        return await call<SessionInfo>("GET", "/session");
      } catch (error) {
        if (error instanceof AuthError && error.code === "unauthenticated") return null;
        throw error;
      }
    },
    listSessions: async () => (await call<{ sessions: DeviceSession[] }>("GET", "/sessions")).sessions,
    revokeSession: (id) => post("/sessions/revoke", { id }),
    revokeOtherSessions: () => post("/sessions/revoke-others"),
    async signOut(opts = {}) {
      try {
        if (opts.everywhere) {
          try {
            await post("/sessions/revoke-others");
          } catch (error) {
            // Signed out already: nothing to revoke, and the call below is still fine.
            if (!(error instanceof AuthError && error.code === "unauthenticated")) throw error;
          }
        }
      } finally {
        await changesSession(() => post("/sign-out"));
      }
    },

    getToken,
  };
}
