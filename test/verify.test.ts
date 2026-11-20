import assert from "node:assert/strict";
import { after, before, beforeEach, describe, test } from "node:test";
import { createTokenVerifier, TokenError, tryVerifyToken, verifyStepUpProof, type TokenErrorCode } from "../src/server/index.ts";
import { claims, fakeAuth, ISSUER, mint, mintHs256, mlDsaSupported, newKey, NOW, publicKeyBytes, type FakeAuth, type TestKey } from "./fake-auth.ts";

let auth: FakeAuth;
let clock: number;
let ed: TestKey;

before(async () => {
  auth = await fakeAuth();
});
after(() => auth.close());
beforeEach(() => {
  clock = NOW;
  ed = newKey("EdDSA");
  auth.jwks.keys = [ed.jwk];
  auth.jwks.status = 200;
  auth.requests.length = 0;
});

const verifier = (extra: Record<string, unknown> = {}) =>
  createTokenVerifier({ issuer: ISSUER, jwksUrl: `${auth.url}/.well-known/jwks.json`, now: () => clock, ...extra });

async function rejects(verify: Promise<unknown>, code: TokenErrorCode): Promise<void> {
  await assert.rejects(verify, (error: unknown) => error instanceof TokenError && error.code === code, `expected ${code}`);
}

describe("verifyToken", () => {
  test("accepts an EdDSA token and returns its claims", async () => {
    const result = await verifier().verify(mint(ed, claims({ email: "ada@example.com", wallet_address: "0xabc" })));
    assert.equal(result.sub, "6f1f3d7e-2f8e-4b0e-9a8e-0d6a2c1f4b11");
    assert.equal(result.email, "ada@example.com");
    assert.equal(result.wallet_address, "0xabc");
  });

  test("accepts an ML-DSA-65 token on a runtime that has it", { skip: !mlDsaSupported() && "no ML-DSA in this Node" }, async () => {
    const pq = newKey("ML-DSA-65");
    auth.jwks.keys = [ed.jwk, pq.jwk];
    const v = verifier();
    assert.equal((await v.verify(mint(pq))).role, "authenticated");
    // An EdDSA token still verifies while the JWKS also lists an ML-DSA key.
    assert.equal((await v.verify(mint(ed))).role, "authenticated");
    // Flip one bit of the signature.
    const token = mint(pq);
    const [h, p, s] = token.split(".") as [string, string, string];
    const bytes = Buffer.from(s, "base64url");
    bytes[0] = bytes[0]! ^ 1;
    await rejects(v.verify(`${h}.${p}.${bytes.toString("base64url")}`), "bad_signature");
  });

  test("names the fix when ML-DSA-65 is not available", async () => {
    const pq = { ...newKey("EdDSA"), alg: "ML-DSA-65" as const, kid: "pq-1", jwk: { kty: "AKP", alg: "ML-DSA-65", kid: "pq-1", use: "sig", pub: "AAAA" } };
    auth.jwks.keys = [ed.jwk, pq.jwk];
    const v = verifier({ loadNodeCrypto: async () => null });
    const token = mint(pq);
    await assert.rejects(v.verify(token), (error: unknown) => error instanceof TokenError && error.code === "ml_dsa_unsupported" && /JWT_ALG=EdDSA/.test(error.message));
    // The EdDSA keys keep working on that runtime.
    assert.ok(await v.verify(mint(ed)));
    await assert.rejects(tryVerifyToken(token, { issuer: ISSUER, jwksUrl: `${auth.url}/.well-known/jwks.json`, loadNodeCrypto: async () => null, now: () => clock }), TokenError);
  });

  test("rejects expired, not yet valid, wrong issuer, wrong audience and missing claims", async () => {
    const v = verifier();
    const sec = NOW / 1000;
    await rejects(v.verify(mint(ed, claims({ exp: sec - 60 }))), "expired");
    await rejects(v.verify(mint(ed, claims({ nbf: sec + 60 }))), "not_yet_valid");
    await rejects(v.verify(mint(ed, claims({ iss: "https://evil.example" }))), "bad_issuer");
    await rejects(v.verify(mint(ed, claims({ aud: "other" }))), "bad_audience");
    await rejects(v.verify(mint(ed, claims({ aud: undefined }))), "bad_audience");
    await rejects(v.verify(mint(ed, claims({ exp: undefined }))), "invalid_claims");
    await rejects(v.verify(mint(ed, claims({ exp: "9999999999" }))), "invalid_claims");
    await rejects(v.verify(mint(ed, claims({ sub: undefined }))), "invalid_claims");
    assert.ok(await v.verify(mint(ed, claims({ aud: ["x", "authenticated"] }))), "an aud list that holds ours is fine");
    // The clock moves: a token good now is expired 11 minutes on, and the tolerance does not stretch to that.
    const token = mint(ed);
    assert.ok(await v.verify(token));
    clock += 11 * 60 * 1000;
    await rejects(v.verify(token), "expired");
  });

  test("honours a custom audience", async () => {
    await rejects(verifier({ audience: "app" }).verify(mint(ed)), "bad_audience");
    assert.ok(await verifier({ audience: "app" }).verify(mint(ed, claims({ aud: "app" }))));
  });

  test("rejects a tampered payload or signature", async () => {
    const [h, , s] = mint(ed).split(".") as [string, string, string];
    const forged = Buffer.from(JSON.stringify(claims({ sub: "someone-else" }))).toString("base64url");
    await rejects(verifier().verify(`${h}.${forged}.${s}`), "bad_signature");
    await rejects(verifier().verify(`${h}.${forged}.${Buffer.alloc(64).toString("base64url")}`), "bad_signature");
  });

  test("rejects algorithm confusion", async () => {
    const v = verifier();
    const other = newKey("EdDSA");
    // alg none, with and without a signature.
    const none = `${Buffer.from('{"alg":"none","kid":"x"}').toString("base64url")}.${Buffer.from(JSON.stringify(claims())).toString("base64url")}.`;
    await rejects(v.verify(none), "unsupported_alg");
    await rejects(v.verify(`${none}AAAA`), "unsupported_alg");
    // HS256 keyed with the public key's bytes (what the JWKS publishes), for every serialisation of it.
    for (const secret of [publicKeyBytes(ed), Buffer.from(ed.jwk.x as string), Buffer.from(ed.jwk.x as string, "base64url")]) {
      await rejects(v.verify(mintHs256(secret, ed.kid)), "unsupported_alg");
    }
    for (const alg of ["RS256", "ES256", "HS512", "ed25519", "eddsa", ""]) {
      await rejects(v.verify(mint(ed, claims(), { header: { alg } })), "unsupported_alg");
    }
    // The header claims ML-DSA-65 over a key the service published as EdDSA, and the reverse.
    await rejects(v.verify(mint(ed, claims(), { header: { alg: "ML-DSA-65" } })), "key_mismatch");
    auth.jwks.keys = [{ ...ed.jwk, alg: "ML-DSA-65" }];
    await rejects(verifier().verify(mint(ed)), "key_mismatch");
    // A JWKS entry whose alg says EdDSA but whose material is not an Ed25519 key.
    auth.jwks.keys = [{ kty: "AKP", alg: "EdDSA", kid: ed.kid, pub: "AAAA" }];
    await rejects(verifier().verify(mint(ed)), "key_mismatch");
    // A key the service never published, even with its own public key in the header: nothing in a token is trusted.
    auth.jwks.keys = [ed.jwk];
    await rejects(v.verify(mint(other, claims(), { header: { jwk: other.jwk, jku: "https://evil.example/jwks.json" } })), "unknown_key");
    // Signed by an attacker's key under our kid.
    await rejects(v.verify(mint(ed, claims(), { signWith: other.privateKey })), "bad_signature");
  });

  test("rejects malformed tokens", async () => {
    const v = verifier();
    const good = mint(ed);
    for (const token of ["", "a.b", "a.b.c.d", "....", `${good}.`, "!!.!!.!!"]) await rejects(v.verify(token), "malformed");
    const [, p, s] = good.split(".") as [string, string, string];
    await rejects(v.verify(`${Buffer.from("[]").toString("base64url")}.${p}.${s}`), "malformed");
    await rejects(v.verify(`${Buffer.from("not json").toString("base64url")}.${p}.${s}`), "malformed");
    await rejects(v.verify(mint(ed, claims(), { header: { crit: ["b64"], b64: false } })), "malformed");
    await rejects(v.verify(mint(ed, claims(), { header: { kid: 7 } })), "unknown_key");
    await rejects(v.verify(mint(ed, claims(), { header: { kid: undefined } })), "unknown_key");
    // A payload that is not an object.
    const input = `${Buffer.from(JSON.stringify({ alg: "EdDSA", kid: ed.kid })).toString("base64url")}.${Buffer.from('"s"').toString("base64url")}`;
    await rejects(v.verify(`${input}.AAAA`), "malformed");
  });
});

describe("JWKS handling", () => {
  test("fetches the JWKS once for many tokens, and again after the cache time", async () => {
    const v = verifier();
    await Promise.all([v.verify(mint(ed)), v.verify(mint(ed)), v.verify(mint(ed))]);
    await v.verify(mint(ed));
    assert.equal(auth.count("GET /.well-known/jwks.json"), 1);
    clock += 299_000;
    await v.verify(mint(ed, claims({ exp: NOW / 1000 + 900 })));
    assert.equal(auth.count("GET /.well-known/jwks.json"), 1);
    clock += 2_000;
    await v.verify(mint(ed, claims({ exp: NOW / 1000 + 900 })));
    assert.equal(auth.count("GET /.well-known/jwks.json"), 2);
  });

  test("picks up a rotated-in key on an unknown kid, but not more often than every 10 seconds", async () => {
    const v = verifier();
    await v.verify(mint(ed));
    const next = newKey("EdDSA");
    auth.jwks.keys = [ed.jwk, next.jwk];
    clock += 11_000;
    assert.ok(await v.verify(mint(next, claims({ iat: clock / 1000, nbf: clock / 1000 - 5, exp: clock / 1000 + 600 }))));
    assert.equal(auth.count("GET /.well-known/jwks.json"), 2);
    // Tokens with kids nobody published make no storm of fetches.
    clock += 1_000;
    for (let i = 0; i < 20; i++) {
      await rejects(v.verify(mint(newKey("EdDSA"), claims({ exp: clock / 1000 + 600 }))), "unknown_key");
    }
    assert.equal(auth.count("GET /.well-known/jwks.json"), 2);
    clock += 10_000;
    await rejects(v.verify(mint(newKey("EdDSA"), claims({ exp: clock / 1000 + 600 }))), "unknown_key");
    assert.equal(auth.count("GET /.well-known/jwks.json"), 3);
  });

  test("a key the service dropped stops verifying once the JWKS is fetched again", async () => {
    const v = verifier();
    const token = mint(ed);
    assert.ok(await v.verify(token));
    auth.jwks.keys = [newKey("EdDSA").jwk];
    clock += 301_000;
    await rejects(v.verify(mint(ed, claims({ exp: clock / 1000 + 600 }))), "unknown_key");
  });

  test("an unreachable JWKS is jwks_unavailable, not an invalid token", async () => {
    auth.jwks.status = 503;
    const v = verifier();
    await rejects(v.verify(mint(ed)), "jwks_unavailable");
    // Not retried on every request while it is down.
    await rejects(v.verify(mint(ed)), "jwks_unavailable");
    assert.equal(auth.count("GET /.well-known/jwks.json"), 1);
    // tryVerifyToken keeps "invalid" (null) apart from "could not tell" (throws).
    const options = { issuer: ISSUER, jwksUrl: `${auth.url}/.well-known/jwks.json`, now: () => clock };
    await assert.rejects(tryVerifyToken(mint(ed), options), (error: unknown) => error instanceof TokenError && error.code === "jwks_unavailable");
    auth.jwks.status = 200;
    clock += 11_000;
    assert.equal(await tryVerifyToken(mint(ed, claims({ exp: 1 })), options), null);
    assert.ok(await tryVerifyToken(mint(ed, claims({ exp: clock / 1000 + 600 })), options));
  });

  test("a cached key keeps verifying through a short outage, and not past the stale limit", async () => {
    const v = verifier();
    await v.verify(mint(ed));
    auth.jwks.status = 503;
    clock += 301_000;
    assert.ok(await v.verify(mint(ed, claims({ exp: clock / 1000 + 600 }))));
    clock += 700_000;
    await rejects(v.verify(mint(ed, claims({ exp: clock / 1000 + 600 }))), "jwks_unavailable");
  });
});

describe("verifyStepUpProof", () => {
  const APP = "https://pay.angler.test";
  const expected = { userId: "6f1f3d7e-2f8e-4b0e-9a8e-0d6a2c1f4b11", sessionId: "a".repeat(32), action: "payout_wallet.approve:42", origin: APP };
  const options = () => ({ issuer: ISSUER, jwksUrl: `${auth.url}/.well-known/jwks.json`, now: () => clock });
  const proof = (overrides: Record<string, unknown> = {}) =>
    mint(ed, claims({ aud: "step-up", role: "step_up", action: expected.action, amr: ["totp"], auth_time: NOW / 1000, origin: APP, exp: NOW / 1000 + 300, ...overrides }));

  test("accepts a proof for this user, action and app", async () => {
    const result = await verifyStepUpProof(proof(), expected, options());
    assert.equal(result.action, expected.action);
    assert.deepEqual(result.amr, ["totp"]);
  });

  test("refuses a proof for another user, action or app, and an access token", async () => {
    await rejects(verifyStepUpProof(proof({ sub: "someone-else" }), expected, options()), "invalid_claims");
    await rejects(verifyStepUpProof(proof({ action: "store.close:1" }), expected, options()), "invalid_claims");
    await rejects(verifyStepUpProof(proof({ origin: "https://news.angler.test" }), expected, options()), "invalid_claims");
    await rejects(verifyStepUpProof(mint(ed, claims()), expected, options()), "bad_audience");
    await rejects(verifyStepUpProof(proof({ role: "authenticated" }), expected, options()), "invalid_claims");
    await rejects(verifyStepUpProof(proof(), { ...expected, sessionId: "b".repeat(32) }, options()), "invalid_claims");
    await assert.rejects(verifyStepUpProof(proof(), { ...expected, sessionId: "" }, options()), TypeError);
    await assert.rejects(verifyStepUpProof(proof({ origin: null }), { ...expected, origin: null as unknown as string }, options()), TypeError);
  });

  test("an access-token check refuses a proof", async () => {
    await rejects(verifier().verify(proof()), "bad_audience");
  });

  test("refuses an old or expired proof", async () => {
    clock = NOW + 400_000;
    await rejects(verifyStepUpProof(proof({ exp: NOW / 1000 + 600 }), expected, options()), "expired");
    await rejects(verifyStepUpProof(proof(), expected, options()), "expired");
  });
});
