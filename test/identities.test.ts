import assert from "node:assert/strict";
import { after, before, beforeEach, describe, test } from "node:test";
import { AuthError, createAuthClient, type AuthClient, type SignInMethod } from "../src/client/index.ts";
import { fakeAuth, NOW, type FakeAuth } from "./fake-auth.ts";

let auth: FakeAuth;

before(async () => {
  auth = await fakeAuth();
});
after(() => auth.close());
beforeEach(() => {
  auth.requests.length = 0;
});

const client = (): AuthClient => createAuthClient({ baseUrl: auth.url, now: () => NOW });
const last = () => auth.requests.at(-1);
const reject = (code: string, status?: number) => (error: unknown) => error instanceof AuthError && error.code === code && (status === undefined || error.status === status);

const stop = { body: { status: "confirmation_required", confirmation: "email" } };
const done = { body: { status: "unlinked", ids: ["solana:abc"], sessionsEnded: 2, signedOut: false } };

const method = (over: Partial<SignInMethod>): SignInMethod => ({ id: "password", kind: "password", label: "Password", createdAt: null, canSignIn: true, removable: true, ...over });

describe("listing sign-in methods", () => {
  test("reads GET /identities", async () => {
    const methods = [method({ id: "email", kind: "email", label: "a@b.co", removable: false, locked: "email" }), method({})];
    auth.on("GET /identities", { body: { methods, confirmation: "email" } });
    const answer = await client().listIdentities();
    assert.deepEqual(answer, { methods, confirmation: "email" });
    assert.equal(last()?.method, "GET");
    assert.equal(last()?.path, "/identities");
  });

  test("a signed-out caller gets unauthenticated", async () => {
    auth.on("GET /identities", { status: 401, body: { error: "unauthenticated" } });
    await assert.rejects(client().listIdentities(), reject("unauthenticated", 401));
  });
});

describe("removing a sign-in method", () => {
  test("an account without a verified email is removed in one call", async () => {
    auth.on("POST /identities/unlink", done);
    const result = await client().unlinkIdentity("solana:abc");
    assert.deepEqual(result, done.body);
    assert.deepEqual(auth.requests.map((r) => r.body), [{ id: "solana:abc" }]);
  });

  test("an emailed code is asked for and the same id goes back with it", async () => {
    let calls = 0;
    auth.on("POST /identities/unlink", () => (++calls === 1 ? stop : done));
    const result = await client().unlinkIdentity("solana:abc", { getConfirmationCode: async () => "012345" });
    assert.equal(result.status, "unlinked");
    assert.deepEqual(auth.requests.map((r) => r.body), [{ id: "solana:abc" }, { id: "solana:abc", code: "012345" }]);
  });

  test("without a way to ask for the code, or with an empty one, it throws and sends nothing more", async () => {
    auth.on("POST /identities/unlink", stop);
    await assert.rejects(client().unlinkIdentity("solana:abc"), reject("confirmation_required"));
    assert.equal(auth.count("POST /identities/unlink"), 1);
    auth.requests.length = 0;
    await assert.rejects(client().unlinkIdentity("solana:abc", { getConfirmationCode: () => "" }), reject("confirmation_required"));
    assert.equal(auth.count("POST /identities/unlink"), 1);
  });

  test("a service that keeps asking for the code is an error, not a loop", async () => {
    auth.on("POST /identities/unlink", stop);
    await assert.rejects(client().unlinkIdentity("solana:abc", { getConfirmationCode: () => "000000" }), reject("confirmation_required"));
    assert.equal(auth.count("POST /identities/unlink"), 2);
  });

  test("the service's refusals are typed errors", async () => {
    for (const [status, error] of [
      [409, "last_sign_in_method"],
      [409, "email_not_removable"],
      [409, "wallet_owner_passkey"],
      [404, "not_found"],
      [403, "reauthentication_required"],
      [401, "unauthenticated"],
      [400, "invalid_code"],
      [429, "rate_limited"],
    ] as const) {
      auth.on("POST /identities/unlink", { status, body: { error } });
      await assert.rejects(client().unlinkIdentity("x", { getConfirmationCode: () => "123456" }), reject(error, status));
    }
  });

  test("tells a caller that its own session ended", async () => {
    auth.on("POST /identities/unlink", { body: { ...done.body, signedOut: true } });
    const result = await client().unlinkIdentity("solana:abc");
    assert.equal(result.signedOut, true);
    assert.equal(result.sessionsEnded, 2);
  });

  test("the provider route takes the code the same way", async () => {
    let calls = 0;
    auth.on("POST /oauth/google/unlink", () => (++calls === 1 ? stop : { body: { status: "unlinked", ids: ["oauth:google:1"], sessionsEnded: 0, signedOut: false } }));
    await client().unlinkOAuth("google", { getConfirmationCode: () => "246810" });
    assert.deepEqual(auth.requests.map((r) => r.body), [{}, { code: "246810" }]);
    auth.requests.length = 0;
    calls = 0;
    await assert.rejects(client().unlinkOAuth("google"), reject("confirmation_required"));
    assert.equal(auth.count("POST /oauth/google/unlink"), 1);
  });
});
