# @angler/auth

TypeScript SDK for [angler-auth](../README.md). No runtime dependencies. ESM only.

| Import | Runs in | What it is |
|---|---|---|
| `@angler/auth/client` | Browser | Sign-in flows, second factor, passkeys, sign-in with Ethereum, sessions, `getToken()` |
| `@angler/auth/server` | Node 22+, Deno, Workers (see below) | `verifyToken`, `getSessionToken`, admin client |
| `@angler/auth/next` | Next.js App Router (server and middleware) | Cookie → token → claims helpers |

It is not published to a registry. Build it with `npm ci && npm run build` in this folder and install the
folder (`npm install ../path/to/angler-auth/sdk`), or add it to a workspace.

Every call that fails throws an `AuthError`: `status` (HTTP status, or `0` when there was no answer),
`code` (the service's `{ "error": code }`, or one of the SDK's own), `retryAfter` (seconds, on `429`) and
`details` (the rest of the body, e.g. `field` or `reason`).

```ts
import { isAuthError } from "@angler/auth/client";

try {
  await auth.signIn({ email, password });
} catch (error) {
  if (isAuthError(error, "email_not_verified")) showCodeForm();
  else if (isAuthError(error, "rate_limited")) wait(error.retryAfter);
  else throw error;
}
```

## Client

```ts
import { createAuthClient } from "@angler/auth/client";

export const auth = createAuthClient({
  baseUrl: "https://auth.angler.network",
  // Only with TURNSTILE_SECRET_KEY set on the service: the widget's token, added to the calls that need one.
  captcha: () => turnstile.getResponse(),
});
```

Every call is `fetch` with `credentials: "include"` and a JSON body. The browser adds the `Origin` header
the service checks, so your page's origin must be in the service's `ALLOWED_ORIGINS`.

### Password, email code, magic link

```ts
await auth.signUp({ email, password, name: "Ada" }); // always "verification_sent"
const result = await auth.verifyEmail({ email, code }); // signs in

const result = await auth.signIn({ email, password });
if (result.status === "mfa_required") {
  await auth.verifyTotp(code); // or auth.verifyRecoveryCode(code), or auth.verifyMfaWithPasskey()
}

await auth.requestEmailCode({ email });
await auth.verifyEmailCode({ email, code }); // creates the account when the address is new

await auth.requestMagicLink({ email, redirect: "https://news.angler.network/home" });
```

A magic link works only in the browser that asked for it and ends on `redirect`, with `?mfa=required` when
the account still owes a second factor. `parseAuthReturn(location.href)` reads that and `?auth_error=<code>`.

`captchaToken` can also be passed to `signUp`, `signIn`, `forgotPassword`, `requestEmailCode` and
`requestMagicLink` one call at a time.

### Google, Apple, Discord, X

OAuth is a redirect, not a request:

```ts
const providers = await auth.providers(); // the ones the service has configured
location.assign(auth.oauthUrl("google", { redirect: location.href }));
```

### Sign-in with Ethereum

The caller supplies the signer. With viem:

```ts
await auth.signInWithEthereum({
  address: account.address,
  chainId: 8453,
  signMessage: (message) => account.signMessage({ message }),
});
```

The message is built here: EIP-4361, `domain` and `uri` from `location` unless you pass them (both must be
the auth host or one of the service's allowed origins). `linkEthereum` attaches a wallet to the signed-in
account. An embedded wallet's address is refused with `embedded_wallet_sign_in`.

### Passkeys

```ts
await auth.signInWithPasskey(); // pass { mediation: "conditional" } to fill from an input's autofill
await auth.registerPasskey({
  name: "Laptop",
  // The service emails a code to accounts with a verified address; the call asks for it here.
  getConfirmationCode: () => prompt("Code from your email"),
});
```

`registerPasskey` returns `recoveryCodes` for an account's first passkey: show them once. Under the strict
policy a classical (non-ML-DSA) passkey signs in only together with TOTP, and `signInWithPasskey` throws
`second_factor_required` for an account without it; sign in another way and use the passkey as the second
step (`verifyMfaWithPasskey`). A dismissed prompt throws `passkey_cancelled`.

### Tokens

```ts
const token = await auth.getToken(); // string | null
```

`getToken()` asks the service for a JWT (10 minutes by default), keeps it in memory and fetches a new one
when it has less than a minute left (`refreshSkewSeconds`). Concurrent calls share one request. It answers
`null` when nobody is signed in or the sign-in still owes its second factor, and throws for anything else
(`rate_limited`, a network error). A sign-in, second factor or sign-out drops the cached token.

### Sessions

```ts
await auth.getSession();                  // null when signed out
await auth.listSessions();                // devices
await auth.revokeSession(id);
await auth.signOut();                     // this browser
await auth.signOut({ everywhere: true }); // every other session first
```

Also on the client: `forgotPassword`, `resetPassword`, `changePassword`, `linkOAuth`, `unlinkOAuth`,
`setupTotp`, `enableTotp`, `disableTotp`, `regenerateRecoveryCodes`, `removePasskey`, `revokeOtherSessions`.

## Server

### Verify a token

```ts
import { verifyToken } from "@angler/auth/server";

const claims = await verifyToken(jwt, { issuer: "https://auth.angler.network", audience: "authenticated" });
claims.sub; claims.email; claims.amr; claims.aal; claims.wallet_address;
```

`issuer` is the service's `AUTH_URL`, character for character; `audience` is `JWT_AUDIENCE` (default
`authenticated`). The signature is checked against `<issuer>/.well-known/jwks.json`, which is kept in the
process for 5 minutes and fetched again when a token names a key id nobody has seen (a rotation), at most
every 10 seconds. A key the service dropped stops verifying at the next fetch. If the JWKS can't be fetched,
a cached key keeps working for 10 more minutes.

`verifyToken` throws a `TokenError` whose `code` says why: `malformed`, `unsupported_alg`, `unknown_key`,
`key_mismatch`, `bad_signature`, `expired`, `not_yet_valid`, `bad_issuer`, `bad_audience`, `invalid_claims`,
`jwks_unavailable`, `ml_dsa_unsupported`. `tryVerifyToken` returns `null` for a token that is simply not
valid and still throws the last two, where the answer is unknown.

Only `EdDSA` (Ed25519, through WebCrypto) and `ML-DSA-65` are accepted. The key is picked by `kid` and its
`alg` must equal the header's, so `none`, `HS*` and a header that relabels a key do not verify.

| Service `JWT_ALG` | Runs on |
|---|---|
| `EdDSA` | Anywhere with WebCrypto Ed25519: Node 22+, Deno, Workers, current browsers |
| `ML-DSA-65` (default) | Node 24.7+ only, through `node:crypto`. Elsewhere `verifyToken` throws `ml_dsa_unsupported`; set `JWT_ALG=EdDSA` on the service |

`node:crypto` is loaded only when an ML-DSA-65 token arrives, so an EdDSA-only deployment never touches it.

For tests or several services, `createTokenVerifier(options)` gives a verifier with its own cache, and
`fetch`/`now` can be injected.

### Token for a request (SSR)

```ts
import { getSessionToken, verifyToken } from "@angler/auth/server";

const jwt = await getSessionToken(request.headers.get("cookie"), {
  authUrl: "https://auth.angler.network",
  origin: "https://news.angler.network", // one of ALLOWED_ORIGINS: the service refuses a POST without it
});
const claims = jwt && (await verifyToken(jwt, { issuer: "https://auth.angler.network" }));
```

Only the `__Secure-angler_session` cookie is forwarded (a name that appears twice goes twice, so the
service sees the planted cookie), never the whole header. The result is `null` when nobody is signed in or
the sign-in owes its second factor, and an `AuthError` when the service can't answer. Keep the JWT on the
server.

### Admin

```ts
import { createAdminClient } from "@angler/auth/server";

const admin = createAdminClient({ authUrl, apiKey: process.env.ADMIN_API_KEY!, adminId: "ada" });
await admin.listUsers({ query: "ada", page: 1, perPage: 50 });
await admin.getUser(id);
await admin.banUser(id, "spam"); // ends every session
await admin.unbanUser(id);
await admin.deleteUser(id);      // has_embedded_wallet (409) for an account that holds one
```

The key never goes to a browser.

## Next.js

```ts
// lib/auth.ts
import { createNextAuth } from "@angler/auth/next";

export const auth = createNextAuth({
  authUrl: "https://auth.angler.network",
  origin: "https://news.angler.network",
});
```

Server component or route handler. `cookies()` can be passed as it is, awaited or not:

```tsx
// app/dashboard/page.tsx
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { cache } from "react";
import { auth } from "@/lib/auth";

// Each call asks the service; cache() makes it one per request.
const currentUser = cache(() => auth.getClaims(cookies()));

export default async function Page() {
  const claims = await currentUser();
  if (!claims) redirect("/sign-in");
  return <p>Hello {claims.email}</p>;
}
```

```ts
// app/api/me/route.ts
export async function GET(request: Request) {
  const claims = await auth.getClaims(request); // a Request, Headers, cookie store or Cookie header
  if (!claims) return Response.json({ error: "unauthenticated" }, { status: 401 });
  return Response.json({ id: claims.sub });
}
```

Middleware. `protect` asks the service on every matched request, so match only the paths that need a
user. `hasSessionCookie` only looks for the cookie: use it to send an obvious stranger to the sign-in page
early, never to let someone in.

```ts
// middleware.ts
import { NextResponse, type NextRequest } from "next/server";
import { auth } from "@/lib/auth";

export async function middleware(request: NextRequest) {
  const denied = await auth.protect(request, { redirectTo: "/sign-in" });
  return denied ?? NextResponse.next();
}

export const config = { matcher: ["/dashboard/:path*"] };
```

On the Edge runtime the JWT must be EdDSA (see above). `@angler/auth/next` does not import `next`.

## PostgREST and supabase-js

The tokens are Supabase compatible: `role: "authenticated"`, `aud`, `sub`. PostgREST (or Supabase) must be
set up to trust the service's JWKS; it can verify only an algorithm it knows, so use `JWT_ALG=EdDSA` on
the service if it can't read ML-DSA-65 (the service README, "Verifying tokens in an app").

Browser. `getToken` is made to be passed as it is, and renews the JWT before PostgREST sees it expire:

```ts
import { createClient } from "@supabase/supabase-js";
import { auth } from "./auth"; // createAuthClient(...)

export const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  accessToken: () => auth.getToken(),
});
// With accessToken, supabase.auth is not used: sign in with `auth` instead.
```

Server, per request (a null token calls PostgREST as the anon role):

```ts
import { getSessionToken } from "@angler/auth/server";

export async function supabaseFor(request: Request) {
  const jwt = await getSessionToken(request.headers.get("cookie"), { authUrl, origin });
  return createClient(SUPABASE_URL, SUPABASE_ANON_KEY, { accessToken: async () => jwt });
}
```

Plain PostgREST needs no library, only the header:

```ts
await fetch(`${POSTGREST_URL}/items`, { headers: { authorization: `Bearer ${jwt}` } });
```

## Not covered

- The wallet host's routes (`/wallet/passkey/*`, `/wallet/embedded/*`, the session handoff): they answer only
  from the wallet origin, to the service's own wallet page.
- Apple's `form_post` callback and the magic-link page: they are served by the service to the browser.
- A server-side client for the signed-in user's own endpoints (`/sessions`, `/mfa/*`, `/passkey/*`): the
  session cookie is not forwarded for them, only for `/token`.
- Publishing to a registry.

## Development

```bash
npm ci
npm run typecheck
npm test        # node:test against a fake server; tokens are minted with local keys
npm run build   # tsc: dist/**/*.js and *.d.ts
```

The tests run the TypeScript source directly (Node 22.18+). ML-DSA tests need Node 24.7+ and are skipped
without it.
