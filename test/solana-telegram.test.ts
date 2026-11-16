import assert from "node:assert/strict";
import { after, before, beforeEach, describe, test } from "node:test";
import { AuthError, buildSiwsMessage, createAuthClient, type AuthClient, type SolanaSigner, type TelegramWidgetData } from "../src/client/index.ts";
import { claims, fakeAuth, mint, newKey, NOW, type FakeAuth } from "./fake-auth.ts";

let auth: FakeAuth;
let clock: number;
const key = newKey("EdDSA");

before(async () => {
  auth = await fakeAuth();
});
after(() => auth.close());
beforeEach(() => {
  clock = NOW;
  auth.requests.length = 0;
});

const client = (): AuthClient => createAuthClient({ baseUrl: auth.url, now: () => clock });
const last = () => auth.requests.at(-1);
const reject = (code: string, status?: number) => (error: unknown) => error instanceof AuthError && error.code === code && (status === undefined || error.status === status);

const ADDRESS = "So11111111111111111111111111111111111111112";
const NONCE = "0123456789abcdef0123456789abcdef";
const SIGNATURE = Uint8Array.from({ length: 64 }, (_, i) => i);
const SIGNATURE_TEXT = Buffer.from(SIGNATURE).toString("base64url");
const ISSUED_AT = "2027-01-15T08:00:00.000Z";
const stop = { body: { status: "confirmation_required", confirmation: "email" } };

const page = { domain: "news.angler.test", uri: "https://news.angler.test" };
const adapter = (messages: string[]): SolanaSigner => ({
  address: ADDRESS,
  ...page,
  signMessage: async (bytes) => (messages.push(new TextDecoder().decode(bytes)), SIGNATURE),
});

describe("Sign-In With Solana", () => {
  test("builds the message the service parses, has the wallet sign its bytes, and sends the signature as base64url", async () => {
    auth.on("POST /solana/nonce", { body: { nonce: NONCE } });
    auth.on("POST /solana/verify", { body: { status: "signed_in", userId: "u" } });
    const messages: string[] = [];
    const result = await client().signInWithSolana(adapter(messages));
    assert.equal(result.status, "signed_in");
    // Pinned on purpose: any change here has to be checked against the service's parseSiwsMessage.
    assert.deepEqual(messages, [
      [
        "news.angler.test wants you to sign in with your Solana account:",
        ADDRESS,
        "",
        "Sign in to Angler.",
        "",
        "URI: https://news.angler.test",
        "Version: 1",
        "Chain ID: mainnet",
        `Nonce: ${NONCE}`,
        `Issued At: ${ISSUED_AT}`,
      ].join("\n"),
    ]);
    assert.deepEqual(auth.requests.map((r) => r.path), ["/solana/nonce", "/solana/verify"]);
    assert.deepEqual(last()?.body, { message: messages[0], signature: SIGNATURE_TEXT });
    assert.equal(SIGNATURE_TEXT.length, 86);
  });

  test("a statement, a chain and an expiry are options; a missing page identity is an error", async () => {
    auth.on("POST /solana/nonce", { body: { nonce: NONCE } });
    auth.on("POST /solana/verify", { body: { status: "signed_in", userId: "u" } });
    const messages: string[] = [];
    await client().signInWithSolana({ ...adapter(messages), statement: "Welcome.", chainId: "devnet", expiresInSeconds: 300 });
    assert.match(messages[0]!, /\n\nWelcome\.\n\nURI: /);
    assert.match(messages[0]!, /\nChain ID: devnet\n/);
    assert.ok(messages[0]!.endsWith(`\nIssued At: ${ISSUED_AT}\nExpiration Time: 2027-01-15T08:05:00.000Z`));
    await assert.rejects(client().signInWithSolana({ address: ADDRESS, signMessage: async () => SIGNATURE }), reject("missing_option"));
  });

  test("a Wallet Standard signIn is given the input, and what it signed is what the service reads", async () => {
    auth.on("POST /solana/nonce", { body: { nonce: NONCE } });
    auth.on("POST /solana/verify", { body: { status: "signed_in", userId: "u" } });
    const inputs: unknown[] = [];
    const wallet = `${page.domain} wants you to sign in with your Solana account:\n${ADDRESS}\n\nWelcome back\n\nURI: ${page.uri}\nVersion: 1\nChain ID: mainnet\nNonce: ${NONCE}\nIssued At: ${ISSUED_AT}`;
    await client().signInWithSolana({
      ...page,
      statement: "Welcome back",
      signIn: async (input) => (inputs.push(input), { signedMessage: new TextEncoder().encode(wallet), signature: SIGNATURE }),
    });
    assert.deepEqual(inputs, [{ domain: page.domain, statement: "Welcome back", uri: page.uri, version: "1", chainId: "mainnet", nonce: NONCE, issuedAt: ISSUED_AT }]);
    assert.deepEqual(last()?.body, { message: wallet, signature: SIGNATURE_TEXT });

    await assert.rejects(
      client().signInWithSolana({ ...page, signIn: async () => ({ signedMessage: Uint8Array.of(0xff, 0xfe), signature: SIGNATURE }) }),
      reject("invalid_message"),
    );
  });

  test("linking sends link, asks for the emailed code, and resends the same message and signature with it", async () => {
    auth.on("POST /solana/nonce", { body: { nonce: NONCE } });
    let calls = 0;
    auth.on("POST /solana/verify", () => (++calls === 1 ? stop : { body: { status: "linked", identity: `solana:${ADDRESS}` } }));
    const messages: string[] = [];
    const result = await client().linkSolana(adapter(messages), { getConfirmationCode: () => "012345" });
    assert.deepEqual(result, { status: "linked", identity: `solana:${ADDRESS}` });
    assert.equal(auth.count("POST /solana/nonce"), 1);
    assert.equal(messages.length, 1);
    const [first, second] = auth.requests.filter((r) => r.path === "/solana/verify");
    assert.deepEqual(first?.body, { message: messages[0], signature: SIGNATURE_TEXT, link: true });
    assert.deepEqual(second?.body, { message: messages[0], signature: SIGNATURE_TEXT, link: true, code: "012345" });
  });

  test("without a way to ask for the code it is an error, and a service that keeps asking is not looped on", async () => {
    auth.on("POST /solana/nonce", { body: { nonce: NONCE } });
    auth.on("POST /solana/verify", stop);
    await assert.rejects(client().linkSolana(adapter([])), reject("confirmation_required"));
    assert.equal(auth.count("POST /solana/verify"), 1);
    auth.requests.length = 0;
    await assert.rejects(client().linkSolana(adapter([]), { getConfirmationCode: () => "000000" }), reject("confirmation_required"));
    assert.equal(auth.count("POST /solana/verify"), 2);
  });

  test("signing in is not a link: a stray confirmation answer is returned, and the service's errors are typed", async () => {
    auth.on("POST /solana/nonce", { body: { nonce: NONCE } });
    auth.on("POST /solana/verify", stop);
    assert.equal((await client().signInWithSolana(adapter([]))).status, "confirmation_required");
    assert.equal(last()?.body?.link, undefined);
    auth.on("POST /solana/verify", { status: 401, body: { error: "invalid_nonce" } });
    await assert.rejects(client().signInWithSolana(adapter([])), reject("invalid_nonce", 401));
    auth.on("POST /solana/verify", { status: 409, body: { error: "already_linked" } });
    await assert.rejects(client().linkSolana(adapter([]), { getConfirmationCode: () => "1" }), reject("already_linked", 409));
  });

  test("a new nonce comes from /solana/nonce, and the message builder writes the layout the wallet does", async () => {
    auth.on("POST /solana/nonce", { body: { nonce: NONCE } });
    assert.deepEqual(await client().solanaNonce(), { nonce: NONCE });
    assert.equal(
      buildSiwsMessage({ domain: "d.test", address: ADDRESS, uri: "https://d.test", chainId: "mainnet", nonce: NONCE, issuedAt: ISSUED_AT, statement: "Hi" }),
      `d.test wants you to sign in with your Solana account:\n${ADDRESS}\n\nHi\n\nURI: https://d.test\nVersion: 1\nChain ID: mainnet\nNonce: ${NONCE}\nIssued At: ${ISSUED_AT}`,
    );
  });

  test("a sign-in drops the cached access token", async () => {
    let issued = 0;
    auth.on("POST /token", () => ({ body: { token: mint(key, claims({ iat: NOW / 1000, exp: NOW / 1000 + 600, jti: `t${++issued}` })), expiresAt: NOW / 1000 + 600 } }));
    auth.on("POST /solana/nonce", { body: { nonce: NONCE } });
    auth.on("POST /solana/verify", { body: { status: "signed_in", userId: "u" } });
    const c = client();
    await c.getToken();
    await c.getToken();
    assert.equal(auth.count("POST /token"), 1);
    await c.signInWithSolana(adapter([]));
    await c.getToken();
    assert.equal(auth.count("POST /token"), 2);
  });
});

describe("Telegram sign-in", () => {
  const widget: TelegramWidgetData = { id: 777000111, first_name: "Ada", username: "ada", auth_date: 1_799_999_000, hash: "ab".repeat(32) };

  test("sends the widget's data unchanged, or the Mini App's initData", async () => {
    auth.on("POST /telegram/verify", { body: { status: "signed_in", userId: "u" } });
    assert.equal((await client().signInWithTelegram({ widget })).status, "signed_in");
    assert.deepEqual(last()?.body, { widget });
    await client().signInWithTelegram({ initData: "auth_date=1&hash=ab" });
    assert.deepEqual(last()?.body, { initData: "auth_date=1&hash=ab" });
  });

  test("the service's refusals are typed errors", async () => {
    for (const [status, code] of [
      [401, "invalid_signature"],
      [400, "expired_auth"],
      [401, "auth_replayed"],
      [404, "not_found"],
    ] as const) {
      auth.on("POST /telegram/verify", { status, body: { error: code } });
      await assert.rejects(client().signInWithTelegram({ widget }), reject(code, status));
    }
  });

  test("linking sends link, asks for the emailed code and resends the same payload with it", async () => {
    let calls = 0;
    auth.on("POST /telegram/verify", () => (++calls === 1 ? stop : { body: { status: "linked", identity: "telegram:777000111" } }));
    const result = await client().linkTelegram({ widget }, { getConfirmationCode: () => "012345" });
    assert.deepEqual(result, { status: "linked", identity: "telegram:777000111" });
    const [first, second] = auth.requests.filter((r) => r.path === "/telegram/verify");
    assert.deepEqual(first?.body, { widget, link: true });
    assert.deepEqual(second?.body, { widget, link: true, code: "012345" });

    auth.on("POST /telegram/verify", stop);
    auth.requests.length = 0;
    await assert.rejects(client().linkTelegram({ widget }), reject("confirmation_required"));
    assert.equal(auth.count("POST /telegram/verify"), 1);
  });

  test("telegramEnabled reads /providers, and an older service without the flag is off", async () => {
    auth.on("GET /providers", { body: { oauth: ["google"], telegram: true } });
    assert.equal(await client().telegramEnabled(), true);
    auth.on("GET /providers", { body: { oauth: ["google"], telegram: false } });
    assert.equal(await client().telegramEnabled(), false);
    auth.on("GET /providers", { body: { oauth: ["google"] } });
    assert.equal(await client().telegramEnabled(), false);
  });
});
