import assert from "node:assert/strict";
import { after, before, beforeEach, describe, test } from "node:test";
import { AuthError, createNextAuth, type NextAuth } from "../src/next/index.ts";
import { APP, claims, fakeAuth, ISSUER, mint, newKey, NOW, type FakeAuth, type TestKey } from "./fake-auth.ts";

const COOKIE = "__Secure-angler_session";

let auth: FakeAuth;
let key: TestKey;
let next: NextAuth;

before(async () => {
  auth = await fakeAuth();
});
after(() => auth.close());
beforeEach(() => {
  key = newKey("EdDSA");
  auth.jwks.keys = [key.jwk];
  auth.requests.length = 0;
  // The service's issuer is its own URL: here, the fake's address.
  auth.on("POST /token", (request) =>
    request.headers.cookie === `${COOKIE}=good`
      ? { body: { token: mint(key, claims({ iss: auth.url, email: "ada@example.com" })), expiresAt: NOW / 1000 + 600 } }
      : { status: 401, body: { error: "unauthenticated" } },
  );
  next = createNextAuth({ authUrl: auth.url, origin: APP, now: () => NOW });
});

/** A cookie store the way `cookies()` of next/headers gives it. */
const store = (...pairs: [string, string][]) => ({ getAll: () => pairs.map(([name, value]) => ({ name, value })) });

describe("createNextAuth", () => {
  test("a signed-in visitor: token, then verified claims, from every kind of source", async () => {
    const sources = [
      `theme=dark; ${COOKIE}=good`,
      new Headers({ cookie: `other=1; ${COOKIE}=good` }),
      new Request(`${APP}/dashboard`, { headers: { cookie: `${COOKIE}=good` } }),
      { headers: new Headers({ cookie: `${COOKIE}=good` }) },
      store(["theme", "dark"], [COOKIE, "good"]),
      Promise.resolve(store([COOKIE, "good"])),
    ];
    for (const source of sources) {
      const claimsOfUser = await next.getClaims(source);
      assert.equal(claimsOfUser?.email, "ada@example.com");
      assert.ok(await next.getToken(source));
    }
    assert.equal(auth.requests.find((r) => r.method === "POST")?.headers.origin, APP);
    assert.equal((await next.requireClaims(`${COOKIE}=good`)).role, "authenticated");
  });

  test("keeps the JWKS between requests", async () => {
    for (let i = 0; i < 5; i++) assert.ok(await next.getClaims(`${COOKIE}=good`));
    assert.equal(auth.count("GET /.well-known/jwks.json"), 1);
  });

  test("forwards only the session cookie from a cookie store, duplicates included", async () => {
    await next.getToken(store(["analytics", "1"], [COOKIE, "good"], [COOKIE, "planted"], ["theme", "dark"]));
    assert.equal(auth.requests[0]?.headers.cookie, `${COOKIE}=good; ${COOKIE}=planted`);
  });

  test("no cookie, or one the service doesn't know: null, and requireClaims throws unauthenticated", async () => {
    assert.equal(await next.getClaims(undefined), null);
    assert.equal(await next.getClaims(store(["theme", "dark"])), null);
    assert.equal(await next.getClaims(`${COOKIE}=stale`), null);
    await assert.rejects(next.requireClaims(`${COOKIE}=stale`), (error: unknown) => error instanceof AuthError && error.status === 401 && error.code === "unauthenticated");
  });

  test("a token for another issuer or audience is not a user", async () => {
    auth.on("POST /token", () => ({ body: { token: mint(key, claims({ iss: ISSUER })), expiresAt: NOW / 1000 + 600 } }));
    assert.equal(await next.getClaims(`${COOKIE}=good`), null);
    auth.on("POST /token", () => ({ body: { token: mint(key, claims({ iss: auth.url, aud: "someone-else" })), expiresAt: NOW / 1000 + 600 } }));
    assert.equal(await next.getClaims(`${COOKIE}=good`), null);
  });

  test("hasSessionCookie only looks", async () => {
    assert.equal(await next.hasSessionCookie(`a=b; ${COOKIE}=whatever`), true);
    assert.equal(await next.hasSessionCookie(store([COOKIE, "x"])), true);
    assert.equal(await next.hasSessionCookie(`x${COOKIE}=1`), false);
    assert.equal(await next.hasSessionCookie(null), false);
    assert.equal(auth.requests.length, 0);
  });

  test("protect lets a signed-in visitor through and answers the others", async () => {
    const request = (cookie?: string) => new Request(`${APP}/dashboard?tab=1`, cookie ? { headers: { cookie } } : {});
    assert.equal(await next.protect(request(`${COOKIE}=good`)), null);

    const anonymous = await next.protect(request());
    assert.equal(anonymous?.status, 401);
    assert.deepEqual(await anonymous?.json(), { error: "unauthenticated" });

    auth.on("POST /token", { status: 401, body: { error: "unauthenticated" } });
    const redirect = await next.protect(request(`${COOKIE}=expired`), { redirectTo: "/sign-in" });
    assert.equal(redirect?.status, 307);
    assert.equal(redirect?.headers.get("location"), `${APP}/sign-in`);
  });

  test("an unreachable service is an error, never a silent sign-out", async () => {
    auth.on("POST /token", { status: 503, body: { error: "busy" } });
    await assert.rejects(next.protect(new Request(`${APP}/x`, { headers: { cookie: `${COOKIE}=good` } })), (error: unknown) => error instanceof AuthError && error.status === 503);
  });
});
