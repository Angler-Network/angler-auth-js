import assert from "node:assert/strict";
import { after, before, beforeEach, describe, test } from "node:test";
import { AuthError, createAuthClient, parseAuthReturn, type AuthClient } from "../src/client/index.ts";
import { claims, fakeAuth, mint, newKey, NOW, type FakeAuth, type Reply } from "./fake-auth.ts";

let auth: FakeAuth;
let clock: number;
let inits: RequestInit[];
const key = newKey("EdDSA");

before(async () => {
  auth = await fakeAuth();
});
after(() => auth.close());
beforeEach(() => {
  clock = NOW;
  inits = [];
  auth.requests.length = 0;
});

function client(extra: Record<string, unknown> = {}): AuthClient {
  return createAuthClient({
    baseUrl: auth.url,
    now: () => clock,
    fetch: (input, init) => {
      if (init) inits.push(init);
      return fetch(input, init);
    },
    ...extra,
  });
}

const last = () => auth.requests.at(-1);
const reject = (code: string, status?: number) => (error: unknown) => error instanceof AuthError && error.code === code && (status === undefined || error.status === status);

/** A /token answer: a token issued `issuedAt` ms and good for `ttl` seconds. */
function tokenReply(issuedAt: number = NOW, ttl = 600): Reply {
  const iat = Math.floor(issuedAt / 1000);
  return { body: { token: mint(key, claims({ iat, nbf: iat - 5, exp: iat + ttl, jti: crypto.randomUUID() })), expiresAt: iat + ttl } };
}

describe("requests", () => {
  test("every call carries credentials and JSON, to the right path", async () => {
    auth.on("POST /password/sign-in", { body: { status: "signed_in", userId: "u1" } });
    auth.on("GET /session", { status: 401, body: { error: "unauthenticated" } });
    const c = client({ baseUrl: `${auth.url}/` });
    assert.deepEqual(await c.signIn({ email: "a@b.co", password: "pw" }), { status: "signed_in", userId: "u1" });
    await c.getSession();
    assert.deepEqual(
      inits.map((init) => [init.method, init.credentials]),
      [
        ["POST", "include"],
        ["GET", "include"],
      ],
    );
    assert.equal(auth.requests[0]?.headers["content-type"], "application/json");
    assert.deepEqual(auth.requests[0]?.body, { email: "a@b.co", password: "pw" });
  });

  test("sign-up, email code, magic link and password reset send what the service reads", async () => {
    for (const route of ["POST /password/sign-up", "POST /password/verify-email", "POST /password/forgot", "POST /password/reset", "POST /email-code/send", "POST /email-code/verify", "POST /magic-link/send"]) {
      auth.on(route, { body: { status: "ok", userId: "u" } });
    }
    const c = client();
    await c.signUp({ email: "a@b.co", password: "pw", name: "Ada", lang: "tr" });
    assert.deepEqual(last()?.body, { email: "a@b.co", password: "pw", name: "Ada", lang: "tr" });
    await c.verifyEmail({ email: "a@b.co", code: "123456" });
    assert.deepEqual([last()?.path, last()?.body], ["/password/verify-email", { email: "a@b.co", code: "123456" }]);
    await c.forgotPassword({ email: "a@b.co" });
    await c.resetPassword({ email: "a@b.co", code: "123456", password: "new-pw" });
    assert.deepEqual([last()?.path, last()?.body], ["/password/reset", { email: "a@b.co", code: "123456", password: "new-pw" }]);
    await c.requestEmailCode({ email: "a@b.co" });
    await c.verifyEmailCode({ email: "a@b.co", code: "654321" });
    assert.deepEqual([last()?.path, last()?.body], ["/email-code/verify", { email: "a@b.co", code: "654321" }]);
    await c.requestMagicLink({ email: "a@b.co", redirect: "https://news.angler.test/home" });
    assert.deepEqual([last()?.path, last()?.body], ["/magic-link/send", { email: "a@b.co", redirect: "https://news.angler.test/home" }]);
  });

  test("passes the captcha token through where the service asks for it, and nowhere else", async () => {
    for (const route of ["POST /password/sign-up", "POST /password/sign-in", "POST /password/forgot", "POST /email-code/send", "POST /magic-link/send", "POST /email-code/verify"]) {
      auth.on(route, { body: { status: "ok" } });
    }
    const c = client({ captcha: async () => "from-widget" });
    await c.signIn({ email: "a@b.co", password: "pw" });
    assert.equal(last()?.body?.captchaToken, "from-widget");
    await c.signIn({ email: "a@b.co", password: "pw", captchaToken: "explicit" });
    assert.equal(last()?.body?.captchaToken, "explicit");
    for (const call of [
      () => c.signUp({ email: "a@b.co", password: "pw" }),
      () => c.forgotPassword({ email: "a@b.co" }),
      () => c.requestEmailCode({ email: "a@b.co" }),
      () => c.requestMagicLink({ email: "a@b.co" }),
    ]) {
      await call();
      assert.equal(last()?.body?.captchaToken, "from-widget", String(last()?.path));
    }
    await c.verifyEmailCode({ email: "a@b.co", code: "111111" });
    assert.equal("captchaToken" in (last()?.body ?? {}), false);
    await client().signIn({ email: "a@b.co", password: "pw" });
    assert.equal("captchaToken" in (last()?.body ?? {}), false);
  });
});

describe("errors", () => {
  test("carry the status, the code and every extra field of the body", async () => {
    auth.on("POST /password/sign-in", { status: 403, body: { error: "email_not_verified" } });
    await assert.rejects(client().signIn({ email: "a@b.co", password: "pw" }), reject("email_not_verified", 403));

    auth.on("POST /password/sign-in", { status: 400, body: { error: "invalid_input", field: "password" } });
    await assert.rejects(client().signIn({ email: "a@b.co", password: "pw" }), (error: unknown) => error instanceof AuthError && error.code === "invalid_input" && error.details.field === "password");

    auth.on("POST /password/sign-in", { status: 429, body: { error: "rate_limited", retryAfter: 42 }, headers: { "retry-after": "42" } });
    await assert.rejects(client().signIn({ email: "a@b.co", password: "pw" }), (error: unknown) => error instanceof AuthError && error.retryAfter === 42 && !("retryAfter" in error.details));

    auth.on("POST /password/sign-in", { status: 429, body: { error: "rate_limited" }, headers: { "retry-after": "9" } });
    await assert.rejects(client().signIn({ email: "a@b.co", password: "pw" }), (error: unknown) => error instanceof AuthError && error.retryAfter === 9);

    for (const code of ["captcha_required", "captcha_failed", "captcha_unavailable", "second_factor_required", "reauthentication_required"]) {
      auth.on("POST /password/sign-in", { status: code === "captcha_unavailable" ? 503 : 403, body: { error: code } });
      await assert.rejects(client().signIn({ email: "a@b.co", password: "pw" }), reject(code));
    }
  });

  test("a dead server and a non-JSON answer are typed too", async () => {
    await assert.rejects(client({ baseUrl: "http://127.0.0.1:1" }).signIn({ email: "a@b.co", password: "pw" }), reject("network_error", 0));
    auth.on("POST /password/sign-in", { status: 200, body: "<html></html>" });
    await assert.rejects(client().signIn({ email: "a@b.co", password: "pw" }), reject("invalid_response", 200));
    auth.on("POST /password/sign-in", { status: 500, body: "boom" });
    await assert.rejects(client().signIn({ email: "a@b.co", password: "pw" }), reject("http_500", 500));
  });
});

describe("getToken", () => {
  test("caches the token and fetches a new one before it expires", async () => {
    auth.on("POST /token", () => tokenReply(clock));
    const c = client();
    const first = await c.getToken();
    assert.ok(first);
    assert.equal(await c.getToken(), first);
    clock += 539_000; // 61 s left of 600
    assert.equal(await c.getToken(), first);
    assert.equal(auth.count("POST /token"), 1);
    clock += 2_000; // 59 s left: inside the refresh window
    const second = await c.getToken();
    assert.notEqual(second, first);
    assert.equal(auth.count("POST /token"), 2);
    assert.equal(await c.getToken({ forceRefresh: true }) === second, false);
    assert.equal(auth.count("POST /token"), 3);
  });

  test("concurrent callers share one request", async () => {
    auth.on("POST /token", () => tokenReply(clock));
    const c = client();
    const tokens = await Promise.all([c.getToken(), c.getToken(), c.getToken()]);
    assert.equal(new Set(tokens).size, 1);
    assert.equal(auth.count("POST /token"), 1);
  });

  test("measures the lifetime on the token, so a wrong device clock changes nothing", async () => {
    // The device is an hour ahead of the service: expiresAt looks long gone, but the token is 10 minutes old at most.
    auth.on("POST /token", () => tokenReply(NOW - 3_600_000));
    const c = client();
    await c.getToken();
    await c.getToken();
    assert.equal(auth.count("POST /token"), 1);
  });

  test("answers null when signed out or waiting for the second factor, and throws for the rest", async () => {
    const c = client();
    auth.on("POST /token", { status: 401, body: { error: "unauthenticated" } });
    assert.equal(await c.getToken(), null);
    auth.on("POST /token", { status: 403, body: { error: "mfa_required" } });
    assert.equal(await c.getToken(), null);
    auth.on("POST /token", { status: 429, body: { error: "rate_limited", retryAfter: 3 } });
    await assert.rejects(c.getToken(), reject("rate_limited", 429));
    auth.on("POST /token", { status: 500, body: { error: "internal_error" } });
    await assert.rejects(c.getToken(), reject("internal_error", 500));
  });

  test("a sign-in, a second factor or a sign-out drops the cached token", async () => {
    auth.on("POST /token", () => tokenReply(clock));
    auth.on("POST /password/sign-in", { body: { status: "mfa_required", userId: "u" } });
    auth.on("POST /mfa/verify", { body: { status: "signed_in" } });
    auth.on("POST /sign-out", { body: { status: "signed_out" } });
    const c = client();
    const before = await c.getToken();
    await c.signIn({ email: "a@b.co", password: "pw" });
    const afterSignIn = await c.getToken();
    assert.notEqual(afterSignIn, before);
    await c.verifyTotp("123456");
    assert.notEqual(await c.getToken(), afterSignIn);
    assert.equal(auth.count("POST /token"), 3);
    await c.signOut();
    auth.on("POST /token", { status: 401, body: { error: "unauthenticated" } });
    assert.equal(await c.getToken(), null);
    assert.equal(auth.count("POST /token"), 4);
  });

  test("a token still on its way when the user signs out is not kept", async () => {
    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => (release = resolve));
    auth.on("POST /token", async () => {
      await gate;
      return tokenReply(clock);
    });
    auth.on("POST /sign-out", { body: { status: "signed_out" } });
    const c = client();
    const pending = c.getToken();
    await c.signOut();
    release();
    await pending;
    auth.on("POST /token", { status: 401, body: { error: "unauthenticated" } });
    assert.equal(await c.getToken(), null, "the old session's token must not be served after sign-out");
  });

  test("works as a callback", async () => {
    auth.on("POST /token", () => tokenReply(clock));
    const { getToken } = client();
    assert.ok(await getToken());
  });
});

describe("session", () => {
  test("getSession is null when signed out", async () => {
    auth.on("GET /session", { status: 401, body: { error: "unauthenticated" } });
    assert.equal(await client().getSession(), null);
    auth.on("GET /session", { body: { status: "mfa_required", session: { methods: ["password"] } } });
    assert.equal((await client().getSession())?.status, "mfa_required");
  });

  test("signOut ends this session, everywhere also the others, and clears the token even if the call fails", async () => {
    auth.on("POST /sign-out", { body: { status: "signed_out" } });
    auth.on("POST /sessions/revoke-others", { body: { status: "revoked" } });
    await client().signOut();
    assert.deepEqual(auth.requests.map((r) => r.path), ["/sign-out"]);
    auth.requests.length = 0;
    await client().signOut({ everywhere: true });
    assert.deepEqual(auth.requests.map((r) => r.path), ["/sessions/revoke-others", "/sign-out"]);

    auth.requests.length = 0;
    auth.on("POST /sessions/revoke-others", { status: 500, body: { error: "internal_error" } });
    await assert.rejects(client().signOut({ everywhere: true }), reject("internal_error"));
    assert.deepEqual(auth.requests.map((r) => r.path), ["/sessions/revoke-others", "/sign-out"], "still signs this browser out");

    auth.requests.length = 0;
    auth.on("POST /sessions/revoke-others", { status: 401, body: { error: "unauthenticated" } });
    await client().signOut({ everywhere: true });
    assert.equal(auth.requests.length, 2);
  });

  test("lists and revokes sessions", async () => {
    auth.on("GET /sessions", { body: { sessions: [{ id: "a".repeat(32), current: true }] } });
    auth.on("POST /sessions/revoke", { body: { status: "revoked" } });
    assert.equal((await client().listSessions())[0]?.current, true);
    await client().revokeSession("b".repeat(32));
    assert.deepEqual(last()?.body, { id: "b".repeat(32) });
  });
});

describe("OAuth", () => {
  test("builds the URL to navigate to", () => {
    const c = createAuthClient({ baseUrl: "https://auth.angler.network/" });
    assert.equal(c.oauthUrl("google"), "https://auth.angler.network/oauth/google");
    assert.equal(c.oauthUrl("discord", { redirect: "https://news.angler.network/a?b=c&d=e" }), "https://auth.angler.network/oauth/discord?redirect=https%3A%2F%2Fnews.angler.network%2Fa%3Fb%3Dc%26d%3De");
  });

  test("lists providers, links and unlinks", async () => {
    auth.on("GET /providers", { body: { oauth: ["google", "x"] } });
    auth.on("POST /oauth/google/link", { body: { url: "https://accounts.google.com/o/oauth2/v2/auth?x=1" } });
    auth.on("POST /oauth/google/unlink", { body: { status: "unlinked" } });
    assert.deepEqual(await client().providers(), ["google", "x"]);
    assert.equal((await client().linkOAuth("google", { redirect: "https://news.angler.test/s" })).url.startsWith("https://accounts.google.com"), true);
    assert.deepEqual(last()?.body, { redirect: "https://news.angler.test/s" });
    await client().unlinkOAuth("google");
    assert.equal(last()?.path, "/oauth/google/unlink");
  });

  test("linking asks for the emailed code and sends it with the same redirect", async () => {
    let calls = 0;
    auth.on("POST /oauth/google/link", () => (++calls === 1 ? { body: { status: "confirmation_required", confirmation: "email" } } : { body: { url: "https://accounts.google.com/o/oauth2/v2/auth?x=1" } }));
    const result = await client().linkOAuth("google", { redirect: "https://news.angler.test/s", getConfirmationCode: async () => "012345" });
    assert.equal(result.url.startsWith("https://accounts.google.com"), true);
    const posts = auth.requests.filter((r) => r.path === "/oauth/google/link");
    assert.deepEqual(posts.map((r) => r.body), [{ redirect: "https://news.angler.test/s" }, { redirect: "https://news.angler.test/s", code: "012345" }]);
    auth.requests.length = 0;
    calls = 0;
    await assert.rejects(client().linkOAuth("google"), reject("confirmation_required"));
    assert.equal(auth.count("POST /oauth/google/link"), 1);
  });

  test("reads what the service left on the return URL", () => {
    assert.deepEqual(parseAuthReturn("https://news.angler.test/?auth_error=link_expired"), { authError: "link_expired", mfaRequired: false });
    assert.deepEqual(parseAuthReturn("https://news.angler.test/home?mfa=required"), { authError: null, mfaRequired: true });
    assert.deepEqual(parseAuthReturn(new URL("https://news.angler.test/")), { authError: null, mfaRequired: false });
    assert.deepEqual(parseAuthReturn("/relative?mfa=required"), { authError: null, mfaRequired: true });
  });
});

describe("second factor", () => {
  test("TOTP and recovery codes go to /mfa/verify", async () => {
    auth.on("POST /mfa/verify", { body: { status: "signed_in" } });
    await client().verifyTotp("123456");
    assert.deepEqual([last()?.path, last()?.body], ["/mfa/verify", { code: "123456" }]);
    await client().verifyRecoveryCode("ABCD-EFGH-IJKL");
    assert.deepEqual([last()?.path, last()?.body], ["/mfa/verify", { recoveryCode: "ABCD-EFGH-IJKL" }]);
    auth.on("POST /mfa/verify", { status: 400, body: { error: "invalid_code" } });
    await assert.rejects(client().verifyTotp("000000"), reject("invalid_code", 400));
  });

  test("enrolment and recovery codes", async () => {
    auth.on("POST /mfa/totp/setup", { body: { secret: "S", uri: "otpauth://totp/x" } });
    auth.on("POST /mfa/totp/enable", { body: { status: "enabled", recoveryCodes: ["a"] } });
    auth.on("POST /mfa/totp/disable", { body: { status: "disabled" } });
    auth.on("POST /mfa/recovery-codes", { body: { recoveryCodes: ["b"] } });
    const c = client();
    assert.equal((await c.setupTotp()).uri, "otpauth://totp/x");
    assert.deepEqual((await c.enableTotp("123456")).recoveryCodes, ["a"]);
    await c.disableTotp({ recoveryCode: "r" });
    assert.deepEqual(last()?.body, { recoveryCode: "r" });
    await c.regenerateRecoveryCodes("123456");
    assert.deepEqual(last()?.body, { code: "123456" });
  });
});

describe("Ethereum", () => {
  const ADDRESS = "0x52908400098527886E0F7030069857D2E4169EE7";

  test("builds the message the service's strict parser takes", async () => {
    auth.on("POST /wallet/nonce", { body: { nonce: "0123456789abcdef0123456789abcdef" } });
    auth.on("POST /wallet/verify", { body: { status: "signed_in", userId: "u" } });
    let signed = "";
    const result = await client().signInWithEthereum({
      address: ADDRESS,
      chainId: 8453,
      domain: "news.angler.test",
      uri: "https://news.angler.test",
      signMessage: async (message) => ((signed = message), `0x${"ab".repeat(65)}`),
    });
    assert.equal(result.status, "signed_in");
    // Pinned on purpose: any change here has to be checked against the service's parseSiweMessage.
    assert.equal(
      signed,
      [
        "news.angler.test wants you to sign in with your Ethereum account:",
        ADDRESS,
        "",
        "Sign in to Angler.",
        "",
        "URI: https://news.angler.test",
        "Version: 1",
        "Chain ID: 8453",
        "Nonce: 0123456789abcdef0123456789abcdef",
        "Issued At: 2027-01-15T08:00:00.000Z",
      ].join("\n"),
    );
    assert.deepEqual(auth.requests.map((r) => r.path), ["/wallet/nonce", "/wallet/verify"]);
    assert.deepEqual(last()?.body, { message: signed, signature: `0x${"ab".repeat(65)}` });
  });

  test("linking sets link, a statement and an expiry are optional, and a missing page identity is an error", async () => {
    auth.on("POST /wallet/nonce", { body: { nonce: "abcdefgh12345678" } });
    auth.on("POST /wallet/verify", { body: { status: "linked", address: ADDRESS.toLowerCase() } });
    let signed = "";
    await client().linkEthereum({
      address: ADDRESS,
      chainId: 1,
      domain: "news.angler.test",
      uri: "https://news.angler.test",
      statement: "Link this wallet.",
      expiresInSeconds: 300,
      signMessage: async (message) => ((signed = message), "0x00"),
    });
    assert.equal(last()?.body?.link, true);
    assert.match(signed, /\n\nLink this wallet\.\n\nURI: /);
    assert.ok(signed.endsWith("\nIssued At: 2027-01-15T08:00:00.000Z\nExpiration Time: 2027-01-15T08:05:00.000Z"));
    await assert.rejects(client().signInWithEthereum({ address: ADDRESS, chainId: 1, signMessage: async () => "0x" }), reject("missing_option"));
  });

  describe("linking with an emailed code", () => {
    const signer = (signed: string[]) => ({
      address: ADDRESS,
      chainId: 1,
      domain: "news.angler.test",
      uri: "https://news.angler.test",
      signMessage: async (message: string) => (signed.push(message), "0xabcd"),
    });
    const stop = { body: { status: "confirmation_required", confirmation: "email" } };

    test("asks for the code and resends the same message and signature with it, without a second nonce or signature", async () => {
      auth.on("POST /wallet/nonce", { body: { nonce: "abcdefgh12345678" } });
      let calls = 0;
      auth.on("POST /wallet/verify", () => (++calls === 1 ? stop : { body: { status: "linked", address: ADDRESS.toLowerCase() } }));
      const signed: string[] = [];
      const result = await client().linkEthereum(signer(signed), { getConfirmationCode: () => "012345" });
      assert.deepEqual(result, { status: "linked", address: ADDRESS.toLowerCase() });
      assert.equal(auth.count("POST /wallet/nonce"), 1);
      assert.equal(signed.length, 1);
      const [first, second] = auth.requests.filter((r) => r.path === "/wallet/verify");
      assert.deepEqual(first?.body, { message: signed[0], signature: "0xabcd", link: true });
      // A string: a number would not match the service's check and would mail another code.
      assert.deepEqual(second?.body, { message: signed[0], signature: "0xabcd", link: true, code: "012345" });
    });

    test("without a way to ask for the code it is an error, and nothing is sent twice", async () => {
      auth.on("POST /wallet/nonce", { body: { nonce: "abcdefgh12345678" } });
      auth.on("POST /wallet/verify", stop);
      await assert.rejects(client().linkEthereum(signer([])), reject("confirmation_required"));
      assert.equal(auth.count("POST /wallet/verify"), 1);
      auth.requests.length = 0;
      await assert.rejects(client().linkEthereum(signer([]), { getConfirmationCode: () => "" }), reject("confirmation_required"));
      assert.equal(auth.count("POST /wallet/verify"), 1);
    });

    test("a wrong code is the service's error, and an answer that asks again is not looped on", async () => {
      auth.on("POST /wallet/nonce", { body: { nonce: "abcdefgh12345678" } });
      auth.on("POST /wallet/verify", (request) => (request.body?.code ? { status: 400, body: { error: "invalid_code" } } : stop));
      await assert.rejects(client().linkEthereum(signer([]), { getConfirmationCode: () => "000000" }), reject("invalid_code", 400));
      auth.on("POST /wallet/verify", stop);
      auth.requests.length = 0;
      await assert.rejects(client().linkEthereum(signer([]), { getConfirmationCode: () => "000000" }), reject("confirmation_required"));
      assert.equal(auth.count("POST /wallet/verify"), 2);
    });

    test("an account without a verified email links in one call and never asks", async () => {
      auth.on("POST /wallet/nonce", { body: { nonce: "abcdefgh12345678" } });
      auth.on("POST /wallet/verify", { body: { status: "linked", address: ADDRESS.toLowerCase() } });
      await client().linkEthereum(signer([]), {
        getConfirmationCode: () => {
          throw new Error("asked");
        },
      });
      assert.equal(auth.count("POST /wallet/verify"), 1);
    });

    test("signing in with a wallet is not a link: a stray confirmation answer is returned, not answered", async () => {
      auth.on("POST /wallet/nonce", { body: { nonce: "abcdefgh12345678" } });
      auth.on("POST /wallet/verify", { body: { status: "signed_in", userId: "u" } });
      assert.equal((await client().signInWithEthereum(signer([]))).status, "signed_in");
      assert.equal(last()?.body?.link, undefined);
    });
  });

  test("a rejected signature is a typed error", async () => {
    auth.on("POST /wallet/nonce", { body: { nonce: "abcdefgh12345678" } });
    auth.on("POST /wallet/verify", { status: 403, body: { error: "embedded_wallet_sign_in" } });
    await assert.rejects(client().signInWithEthereum({ address: ADDRESS, chainId: 1, domain: "d", uri: "https://d", signMessage: async () => "0x00" }), reject("embedded_wallet_sign_in", 403));
  });
});

describe("passkeys", () => {
  const bytes = (...values: number[]) => Uint8Array.from(values).buffer;
  const b64 = (...values: number[]) => Buffer.from(values).toString("base64url");

  function fakeCredentials(overrides: { create?: () => Promise<unknown>; get?: () => Promise<unknown> } = {}) {
    const calls: { create: unknown[]; get: unknown[] } = { create: [], get: [] };
    const container = {
      async create(options: unknown) {
        calls.create.push(options);
        if (overrides.create) return overrides.create();
        return {
          id: "cred-1",
          rawId: bytes(1, 2, 3),
          type: "public-key",
          response: { clientDataJSON: bytes(4, 5), attestationObject: bytes(6, 7, 8), getTransports: () => ["internal", "hybrid"] },
        };
      },
      async get(options: unknown) {
        calls.get.push(options);
        if (overrides.get) return overrides.get();
        return {
          id: "cred-1",
          rawId: bytes(1, 2, 3),
          type: "public-key",
          response: { clientDataJSON: bytes(4, 5), authenticatorData: bytes(9, 9), signature: bytes(250, 251), userHandle: bytes(7) },
        };
      },
    };
    return { container: container as unknown as CredentialsContainer, calls };
  }

  const registration = (confirmation: "email" | "none") => ({
    challenge: b64(10, 11, 12),
    rp: { id: "angler.test", name: "Angler" },
    user: { id: b64(1, 1), name: "ada@example.com", displayName: "Ada" },
    pubKeyCredParams: [{ type: "public-key", alg: -49 }],
    timeout: 300000,
    attestation: "none",
    authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "required" },
    excludeCredentials: [{ type: "public-key", id: b64(200, 201), transports: ["usb"] }],
    confirmation,
  });

  test("registers: base64url options become buffers and the credential goes back as base64url", async () => {
    auth.on("POST /passkey/register/options", { body: registration("none") });
    auth.on("POST /passkey/register/verify", { body: { status: "registered", id: "x", postQuantum: false, recoveryCodes: ["r1"] } });
    const { container, calls } = fakeCredentials();
    const result = await client({ credentials: container }).registerPasskey({ name: "Laptop", lang: "tr" });
    assert.deepEqual(result.recoveryCodes, ["r1"]);
    assert.deepEqual(auth.requests[0]?.body, { lang: "tr" });

    const options = (calls.create[0] as { publicKey: PublicKeyCredentialCreationOptions }).publicKey;
    assert.deepEqual([...new Uint8Array(options.challenge as ArrayBuffer)], [10, 11, 12]);
    assert.deepEqual([...new Uint8Array(options.user.id as ArrayBuffer)], [1, 1]);
    assert.deepEqual([...new Uint8Array(options.excludeCredentials?.[0]?.id as ArrayBuffer)], [200, 201]);
    assert.deepEqual(options.excludeCredentials?.[0]?.transports, ["usb"]);
    assert.equal(options.attestation, "none");
    assert.equal(options.authenticatorSelection?.residentKey, "required");

    assert.deepEqual(last()?.body, {
      credential: { id: "cred-1", rawId: b64(1, 2, 3), type: "public-key", response: { clientDataJSON: b64(4, 5), attestationObject: b64(6, 7, 8), transports: ["internal", "hybrid"] } },
      name: "Laptop",
    });
  });

  test("an emailed confirmation code is asked for and sent; without a way to ask, it is an error", async () => {
    auth.on("POST /passkey/register/options", { body: registration("email") });
    auth.on("POST /passkey/register/verify", { body: { status: "registered", id: "x", postQuantum: true } });
    const { container } = fakeCredentials();
    await client({ credentials: container }).registerPasskey({ getConfirmationCode: async () => "123456" });
    assert.equal(last()?.body?.code, "123456");
    auth.requests.length = 0;
    await assert.rejects(client({ credentials: container }).registerPasskey(), reject("confirmation_required"));
    assert.equal(auth.count("POST /passkey/register/verify"), 0);
  });

  test("signs in with an assertion", async () => {
    auth.on("POST /passkey/login/options", { body: { challenge: b64(1, 2), rpId: "angler.test", timeout: 300000, userVerification: "required", allowCredentials: [] } });
    auth.on("POST /passkey/login/verify", { body: { status: "signed_in", userId: "u" } });
    const { container, calls } = fakeCredentials();
    const result = await client({ credentials: container }).signInWithPasskey({ mediation: "conditional" });
    assert.equal(result.userId, "u");
    const request = calls.get[0] as { publicKey: PublicKeyCredentialRequestOptions; mediation: string };
    assert.equal(request.mediation, "conditional");
    assert.equal(request.publicKey.rpId, "angler.test");
    assert.deepEqual(last()?.body, {
      credential: { id: "cred-1", rawId: b64(1, 2, 3), type: "public-key", response: { clientDataJSON: b64(4, 5), authenticatorData: b64(9, 9), signature: b64(250, 251), userHandle: b64(7) } },
    });
  });

  test("an empty user handle is left out", async () => {
    auth.on("POST /passkey/login/options", { body: { challenge: b64(1, 2), rpId: "angler.test", timeout: 1, userVerification: "required", allowCredentials: [] } });
    auth.on("POST /passkey/login/verify", { body: { status: "signed_in", userId: "u" } });
    const { container } = fakeCredentials({
      get: async () => ({ id: "c", rawId: bytes(1), type: "public-key", response: { clientDataJSON: bytes(1), authenticatorData: bytes(2), signature: bytes(3), userHandle: bytes() } }),
    });
    await client({ credentials: container }).signInWithPasskey();
    assert.equal("userHandle" in ((last()?.body?.credential as { response: object }).response), false);
  });

  test("a passkey as the second factor uses the MFA endpoints and its allow list", async () => {
    auth.on("POST /mfa/passkey/options", { body: { challenge: b64(3), rpId: "angler.test", timeout: 1, userVerification: "required", allowCredentials: [{ type: "public-key", id: b64(5, 6) }] } });
    auth.on("POST /mfa/passkey/verify", { body: { status: "signed_in" } });
    const { container, calls } = fakeCredentials();
    assert.equal((await client({ credentials: container }).verifyMfaWithPasskey()).status, "signed_in");
    const allowed = (calls.get[0] as { publicKey: PublicKeyCredentialRequestOptions }).publicKey.allowCredentials;
    assert.deepEqual([...new Uint8Array(allowed?.[0]?.id as ArrayBuffer)], [5, 6]);
    assert.equal(last()?.path, "/mfa/passkey/verify");
  });

  test("a dismissed prompt is passkey_cancelled, and a browser without WebAuthn is passkeys_unsupported", async () => {
    auth.on("POST /passkey/login/options", { body: { challenge: b64(1, 2), rpId: "angler.test", timeout: 1, userVerification: "required", allowCredentials: [] } });
    const cancelled = fakeCredentials({ get: async () => Promise.reject(new DOMException("denied", "NotAllowedError")) });
    await assert.rejects(client({ credentials: cancelled.container }).signInWithPasskey(), reject("passkey_cancelled", 0));
    const none = fakeCredentials({ get: async () => null });
    await assert.rejects(client({ credentials: none.container }).signInWithPasskey(), reject("passkey_cancelled"));
    await assert.rejects(client().signInWithPasskey(), reject("passkeys_unsupported"));
  });

  test("removes a passkey with the emailed code", async () => {
    auth.on("POST /passkey/remove/options", { body: { confirmation: "email" } });
    auth.on("POST /passkey/remove", { body: { status: "removed" } });
    await client().removePasskey("pk-1", { getConfirmationCode: () => "654321" });
    assert.deepEqual(last()?.body, { id: "pk-1", code: "654321" });
    auth.on("POST /passkey/remove/options", { body: { confirmation: "none" } });
    await client().removePasskey("pk-1");
    assert.deepEqual(last()?.body, { id: "pk-1" });
  });
});
