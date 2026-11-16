import { base64urlEncode, decodeJwtPart } from "../base64url.ts";
import { AuthError } from "../errors.ts";
import { joinUrl, requestJson } from "../http.ts";
import type { AccountInfo, AuthMethod, Language, OAuthProvider, SignInMethod } from "../types.ts";
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
import { buildSiwsMessage, DEFAULT_SIWS_STATEMENT } from "./solana.ts";

export { AuthError, isAuthError } from "../errors.ts";
export type { AuthErrorCode, AuthErrorInit } from "../errors.ts";
export type { AccountInfo, AuthClaims, AuthMethod, Language, OAuthProvider, SignInMethod, SignInMethodKind, WalletInfo } from "../types.ts";
export { buildSiweMessage, DEFAULT_SIWE_STATEMENT, type SiweMessageInput } from "./siwe.ts";
export { buildSiwsMessage, DEFAULT_SIWS_STATEMENT, type SiwsMessageInput } from "./solana.ts";

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

/** What Wallet Standard's `solana:signIn` takes. */
export interface SolanaSignInInput {
  domain: string;
  address?: string;
  statement: string;
  uri: string;
  version: "1";
  chainId: string;
  nonce: string;
  issuedAt: string;
  expirationTime?: string;
}

/** What Wallet Standard's `solana:signIn` gives back. */
export interface SolanaSignInOutput {
  signedMessage: Uint8Array;
  signature: Uint8Array;
}

/**
 * A Solana wallet. Give `signIn` (Wallet Standard, Phantom: the wallet builds and signs the message) or `address` and
 * `signMessage` (wallet-adapter: the SDK builds the message and the wallet signs its bytes, giving the 64-byte signature).
 */
export type SolanaSigner = {
  /** Defaults to `mainnet`. Must be one of the service's `SOLANA_CHAIN_IDS`. */
  chainId?: string;
  /** Defaults to the page's `location.host` and `location.origin`; both must be allowed by the service. */
  domain?: string;
  uri?: string;
  statement?: string;
  /** Seconds the message stays valid. Default: the service's own limit (10 minutes). */
  expiresInSeconds?: number;
} & (
  | { address: string; signMessage: (message: Uint8Array) => Promise<Uint8Array> }
  | { address?: string; signIn: (input: SolanaSignInInput) => Promise<SolanaSignInOutput> }
);

/** The Login Widget's `onauth` object, exactly as Telegram gave it: every field is signed, so none may be edited or left out. */
export interface TelegramWidgetData {
  id: number | string;
  auth_date: number | string;
  hash: string;
  [field: string]: string | number | undefined;
}

/** The Login Widget's data, or a Mini App's `Telegram.WebApp.initData` string. */
export type TelegramLogin = { widget: TelegramWidgetData } | { initData: string };

export interface ConfirmationCallback {
  /** Asked for the emailed code when the service says one was sent. Without it the call throws `confirmation_required`. */
  getConfirmationCode?: () => string | Promise<string>;
}

/** What a removal answers. `signedOut` is true when the session that asked signed in with the removed kind and ended too. */
export interface UnlinkResult {
  status: "unlinked";
  ids: string[];
  /** Sessions of the account that ended, this one included. */
  sessionsEnded: number;
  signedOut: boolean;
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
  /**
   * `{ url }` to navigate to. Needs a recent sign-in. An account with a verified email gets a code mailed first:
   * `getConfirmationCode` asks for it, and without it the call throws `confirmation_required`.
   */
  linkOAuth(provider: OAuthProvider, options?: { redirect?: string } & ConfirmationCallback): Promise<{ url: string }>;
  /**
   * Removes every account of the provider, by the rules of `unlinkIdentity` (a recent sign-in, the emailed code, never the
   * last way in).
   */
  unlinkOAuth(provider: OAuthProvider, options?: ConfirmationCallback): Promise<UnlinkResult>;

  // sign-in methods
  /** The account's ways to sign in, and which of them can be removed now. `confirmation` says whether removing needs the emailed code. */
  listIdentities(): Promise<{ methods: SignInMethod[]; confirmation: "email" | "none" }>;
  /**
   * Removes one method (`id` from `listIdentities`). Needs a recent sign-in. An account with a verified email gets a code
   * mailed first: `getConfirmationCode` asks for it, and without it the call throws `confirmation_required`. Fails with
   * `last_sign_in_method` when nothing else could sign in, `email_not_removable` and `wallet_owner_passkey` for the two
   * that are fixed, and `not_found` for an id the account doesn't have. Every session that signed in with the same kind
   * of method ends, this one too when it is one of them: check `signedOut`.
   */
  unlinkIdentity(id: string, options?: ConfirmationCallback): Promise<UnlinkResult>;

  // wallets
  /** One-time nonce for an EIP-4361 message. */
  siweNonce(): Promise<{ nonce: string }>;
  /** Builds the message, has the caller sign it and verifies it. Creates the account when the wallet is new. */
  signInWithEthereum(signer: EthereumSigner): Promise<SignInResult>;
  /**
   * Attaches the wallet to the signed-in account. Needs a recent sign-in. An account with a verified email gets a
   * code mailed first: `getConfirmationCode` asks for it (the wallet is not asked to sign again), and without it
   * the call throws `confirmation_required`.
   */
  linkEthereum(signer: EthereumSigner, options?: ConfirmationCallback): Promise<{ status: "linked"; address: string }>;

  // Solana wallets
  /** One-time nonce for a Sign-In With Solana message. */
  solanaNonce(): Promise<{ nonce: string }>;
  /** Has the wallet sign a message and verifies it. Creates the account (no email) when the wallet is new. */
  signInWithSolana(signer: SolanaSigner): Promise<SignInResult>;
  /**
   * Attaches the wallet to the signed-in account. Needs a recent sign-in. An account with a verified email gets a
   * code mailed first: `getConfirmationCode` asks for it (the wallet is not asked to sign again), and without it
   * the call throws `confirmation_required`.
   */
  linkSolana(signer: SolanaSigner, options?: ConfirmationCallback): Promise<{ status: "linked"; identity: string }>;

  // Telegram
  /** Whether the service has Telegram sign-in on (`TELEGRAM_BOT_TOKEN`); otherwise its routes answer `not_found`. */
  telegramEnabled(): Promise<boolean>;
  /** Creates the account (no email) when the Telegram user is new. A payload works once. */
  signInWithTelegram(login: TelegramLogin): Promise<SignInResult>;
  /** Attaches the Telegram account to the signed-in account; the emailed code works as for `linkSolana`. */
  linkTelegram(login: TelegramLogin, options?: ConfirmationCallback): Promise<{ status: "linked"; identity: string }>;

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

  /** The service mailed a code and waits for it to come back as `code`. */
  const wantsEmailCode = (answer: unknown): boolean =>
    typeof answer === "object" && answer !== null && (answer as { confirmation?: unknown }).confirmation === "email";

  /** The emailed code as a string (the service ignores any other type), or `confirmation_required`. */
  async function emailedCode(callback: ConfirmationCallback): Promise<string> {
    const code = await confirmationCode(true, callback);
    if (typeof code !== "string" || code === "") throw new AuthError({ status: 0, code: "confirmation_required" });
    return code;
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
  async function ethereum<T>(signer: EthereumSigner, link: boolean, callback: ConfirmationCallback = {}): Promise<T> {
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
    return changesSession(() => verifyLinkable<T>("/wallet/verify", { message, signature }, link, callback));
  }

  /**
   * A call that signs in, or links with `link`. The service may stop before it uses anything single-use and ask for the
   * emailed code: the same body goes back with it, so the wallet or Telegram does not sign twice.
   */
  async function verifyLinkable<T>(path: string, payload: Record<string, unknown>, link: boolean, callback: ConfirmationCallback): Promise<T> {
    const body = { ...payload, ...(link ? { link: true } : {}) };
    const answer = await post<T>(path, body);
    if (!link || !wantsEmailCode(answer)) return answer;
    const again = await post<T>(path, { ...body, code: await emailedCode(callback) });
    if (wantsEmailCode(again)) throw new AuthError({ status: 200, code: "confirmation_required" });
    return again;
  }

  // --- SIWS ---
  async function solana<T>(signer: SolanaSigner, link: boolean, callback: ConfirmationCallback = {}): Promise<T> {
    const domain = signer.domain ?? pageIdentity().domain;
    const uri = signer.uri ?? pageIdentity().uri;
    const chainId = signer.chainId ?? "mainnet";
    const statement = signer.statement ?? DEFAULT_SIWS_STATEMENT;
    const { nonce } = await post<{ nonce: string }>("/solana/nonce");
    const issued = new Date(now());
    const issuedAt = issued.toISOString();
    const expirationTime = signer.expiresInSeconds ? new Date(issued.getTime() + signer.expiresInSeconds * 1000).toISOString() : undefined;

    let message: string;
    let signature: Uint8Array;
    if ("signIn" in signer) {
      const output = await signer.signIn({
        domain,
        ...(signer.address ? { address: signer.address } : {}),
        statement,
        uri,
        version: "1",
        chainId,
        nonce,
        issuedAt,
        ...(expirationTime ? { expirationTime } : {}),
      });
      // The wallet may word the message its own way: what it signed is what the service reads.
      try {
        message = new TextDecoder("utf-8", { fatal: true }).decode(output.signedMessage);
      } catch {
        throw new AuthError({ status: 0, code: "invalid_message" });
      }
      signature = output.signature;
    } else {
      message = buildSiwsMessage({ domain, uri, address: signer.address, chainId, nonce, issuedAt, statement, ...(expirationTime ? { expirationTime } : {}) });
      signature = await signer.signMessage(new TextEncoder().encode(message));
    }
    return changesSession(() => verifyLinkable<T>("/solana/verify", { message, signature: base64urlEncode(signature) }, link, callback));
  }

  async function telegram<T>(login: TelegramLogin, link: boolean, callback: ConfirmationCallback = {}): Promise<T> {
    return changesSession(() => verifyLinkable<T>("/telegram/verify", { ...login }, link, callback));
  }

  /** A removal: the service mails a code on the first call and takes the same body with `code` on the second. */
  async function unlink(path: string, body: Record<string, unknown>, callback: ConfirmationCallback): Promise<UnlinkResult> {
    return changesSession(async () => {
      const answer = await post<UnlinkResult>(path, body);
      if (!wantsEmailCode(answer)) return answer;
      const again = await post<UnlinkResult>(path, { ...body, code: await emailedCode(callback) });
      if (wantsEmailCode(again)) throw new AuthError({ status: 200, code: "confirmation_required" });
      return again;
    });
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
    async linkOAuth(provider, opts = {}) {
      const body = opts.redirect ? { redirect: opts.redirect } : {};
      const answer = await post<{ url: string }>(`/oauth/${provider}/link`, body);
      if (!wantsEmailCode(answer)) return answer;
      const again = await post<{ url: string }>(`/oauth/${provider}/link`, { ...body, code: await emailedCode(opts) });
      if (wantsEmailCode(again)) throw new AuthError({ status: 200, code: "confirmation_required" });
      return again;
    },
    unlinkOAuth: (provider, opts = {}) => unlink(`/oauth/${provider}/unlink`, {}, opts),
    listIdentities: () => call("GET", "/identities"),
    unlinkIdentity: (id, opts = {}) => unlink("/identities/unlink", { id }, opts),

    siweNonce: () => post("/wallet/nonce"),
    signInWithEthereum: (signer) => ethereum<SignInResult>(signer, false),
    linkEthereum: (signer, opts) => ethereum<{ status: "linked"; address: string }>(signer, true, opts),

    solanaNonce: () => post("/solana/nonce"),
    signInWithSolana: (signer) => solana<SignInResult>(signer, false),
    linkSolana: (signer, opts) => solana<{ status: "linked"; identity: string }>(signer, true, opts),

    telegramEnabled: async () => (await call<{ telegram?: boolean }>("GET", "/providers")).telegram === true,
    signInWithTelegram: (login) => telegram<SignInResult>(login, false),
    linkTelegram: (login, opts) => telegram<{ status: "linked"; identity: string }>(login, true, opts),

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
