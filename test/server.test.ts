import assert from "node:assert/strict";
import { after, before, beforeEach, describe, test } from "node:test";
import { AuthError, createAdminClient, createTokenVerifier, getSessionToken, sessionCookiePairs } from "../src/server/index.ts";
import { APP, claims, fakeAuth, ISSUER, mint, newKey, NOW, type FakeAuth } from "./fake-auth.ts";

let auth: FakeAuth;
before(async () => {
  auth = await fakeAuth();
});
after(() => auth.close());
beforeEach(() => {
  auth.requests.length = 0;
});

const COOKIE = "__Secure-angler_session";

describe("getSessionToken", () => {
  test("forwards only the session cookie, with the app's Origin, and returns the token", async () => {
    auth.on("POST /token", { body: { token: "jwt-1", expiresAt: 1 } });
    const header = `theme=dark; ${COOKIE}=abc123_-xyz; x${COOKIE}=lookalike; ${COOKIE}x=lookalike2; analytics=1; __Host-angler_session=hostcopy`;
    assert.equal(await getSessionToken(header, { authUrl: auth.url, origin: APP }), "jwt-1");
    const [request] = auth.requests;
    assert.equal(request?.method, "POST");
    assert.equal(request?.headers.cookie, `${COOKIE}=abc123_-xyz`);
    assert.equal(request?.headers.origin, APP);
  });

  test("normalises the origin and honours a trailing slash on the auth URL", async () => {
    auth.on("POST /token", { body: { token: "jwt-2", expiresAt: 1 } });
    assert.equal(await getSessionToken(`${COOKIE}=a`, { authUrl: `${auth.url}/`, origin: `${APP}/` }), "jwt-2");
    assert.equal(auth.requests[0]?.headers.origin, APP);
  });

  test("a name that appears twice goes through twice, so the service sees the planted cookie", async () => {
    assert.deepEqual(sessionCookiePairs(`${COOKIE}=real; a=b; ${COOKIE}=planted`), [`${COOKIE}=real`, `${COOKIE}=planted`]);
    auth.on("POST /token", { status: 401, body: { error: "unauthenticated" } });
    assert.equal(await getSessionToken(`${COOKIE}=real; ${COOKIE}=planted`, { authUrl: auth.url, origin: APP }), null);
    assert.equal(auth.requests[0]?.headers.cookie, `${COOKIE}=real; ${COOKIE}=planted`);
  });

  test("makes no call without the cookie", async () => {
    for (const header of [undefined, null, "", "a=b", `x${COOKIE}=1`, `${COOKIE}`]) {
      assert.equal(await getSessionToken(header, { authUrl: auth.url, origin: APP }), null);
    }
    assert.equal(auth.requests.length, 0);
  });

  test("answers null when signed out or waiting for the second factor, and throws for the rest", async () => {
    const options = { authUrl: auth.url, origin: APP };
    auth.on("POST /token", { status: 401, body: { error: "unauthenticated" } });
    assert.equal(await getSessionToken(`${COOKIE}=a`, options), null);
    auth.on("POST /token", { status: 403, body: { error: "mfa_required" } });
    assert.equal(await getSessionToken(`${COOKIE}=a`, options), null);

    auth.on("POST /token", { status: 429, body: { error: "rate_limited", retryAfter: 7 }, headers: { "retry-after": "7" } });
    await assert.rejects(getSessionToken(`${COOKIE}=a`, options), (error: unknown) => error instanceof AuthError && error.status === 429 && error.code === "rate_limited" && error.retryAfter === 7);
    auth.on("POST /token", { status: 403, body: { error: "invalid_origin" } });
    await assert.rejects(getSessionToken(`${COOKIE}=a`, options), (error: unknown) => error instanceof AuthError && error.code === "invalid_origin");
    auth.on("POST /token", { status: 502, body: "<html>bad gateway</html>" });
    await assert.rejects(getSessionToken(`${COOKIE}=a`, options), (error: unknown) => error instanceof AuthError && error.status === 502 && error.code === "http_502");
    auth.on("POST /token", { body: { nope: true } });
    await assert.rejects(getSessionToken(`${COOKIE}=a`, options), (error: unknown) => error instanceof AuthError && error.code === "invalid_response");
    await assert.rejects(getSessionToken(`${COOKIE}=a`, { authUrl: "http://127.0.0.1:1", origin: APP }), (error: unknown) => error instanceof AuthError && error.code === "network_error" && error.status === 0);
  });

  test("the token it returns verifies against the JWKS, end to end", async () => {
    const key = newKey("EdDSA");
    auth.jwks.keys = [key.jwk];
    auth.on("POST /token", () => ({ body: { token: mint(key, claims({ amr: ["password", "totp"], aal: "aal2" })), expiresAt: NOW / 1000 + 600 } }));
    const token = await getSessionToken(`${COOKIE}=a`, { authUrl: auth.url, origin: APP });
    assert.ok(token);
    const verified = await createTokenVerifier({ issuer: ISSUER, jwksUrl: `${auth.url}/.well-known/jwks.json`, now: () => NOW }).verify(token);
    assert.deepEqual(verified.amr, ["password", "totp"]);
    assert.equal(verified.aal, "aal2");
  });
});

describe("admin client", () => {
  const ID = "6f1f3d7e-2f8e-4b0e-9a8e-0d6a2c1f4b11";
  const admin = () => createAdminClient({ authUrl: auth.url, apiKey: "k".repeat(40), adminId: "admin-7" });

  test("sends the key and the admin id, and builds the list query", async () => {
    auth.on("GET /admin/users", { body: { users: [], total: 0, page: 2, perPage: 10 } });
    assert.deepEqual(await admin().listUsers({ query: "ada lovelace&x", page: 2, perPage: 10 }), { users: [], total: 0, page: 2, perPage: 10 });
    const [request] = auth.requests;
    assert.equal(request?.path, "/admin/users?query=ada+lovelace%26x&page=2&perPage=10");
    assert.equal(request?.headers.authorization, `Bearer ${"k".repeat(40)}`);
    assert.equal(request?.headers["x-admin-id"], "admin-7");
    assert.equal(request?.headers.origin, undefined);
    await admin().listUsers();
    assert.equal(auth.requests[1]?.path, "/admin/users");
  });

  test("reads, bans, unbans and deletes", async () => {
    auth.on(`GET /admin/users/${ID}`, { body: { user: { id: ID, email: "ada@example.com", account: { hasPassword: true } } } });
    auth.on(`POST /admin/users/${ID}/ban`, (request) => ({ body: { status: request.body?.banned ? "banned" : "unbanned" } }));
    auth.on(`POST /admin/users/${ID}/delete`, { body: { status: "deleted" } });
    assert.equal((await admin().getUser(ID)).email, "ada@example.com");
    assert.deepEqual(await admin().banUser(ID, "spam"), { status: "banned" });
    assert.deepEqual(auth.requests.at(-1)?.body, { banned: true, reason: "spam" });
    assert.deepEqual(await admin().unbanUser(ID), { status: "unbanned" });
    assert.deepEqual(auth.requests.at(-1)?.body, { banned: false });
    assert.deepEqual(await admin().deleteUser(ID), { status: "deleted" });
  });

  test("turns the service's errors into AuthError and refuses a malformed id before any call", async () => {
    auth.on(`POST /admin/users/${ID}/delete`, { status: 409, body: { error: "has_embedded_wallet" } });
    await assert.rejects(admin().deleteUser(ID), (error: unknown) => error instanceof AuthError && error.status === 409 && error.code === "has_embedded_wallet");
    auth.on("GET /admin/users", { status: 401, body: { error: "invalid_admin_key" } });
    await assert.rejects(admin().listUsers(), (error: unknown) => error instanceof AuthError && error.code === "invalid_admin_key");
    auth.requests.length = 0;
    for (const id of ["", "../sessions", `${ID}/ban`, "not-a-uuid"]) {
      await assert.rejects(admin().getUser(id), (error: unknown) => error instanceof AuthError && error.code === "invalid_input");
    }
    assert.equal(auth.requests.length, 0);
  });
});
