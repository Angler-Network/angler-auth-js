import { createHmac, generateKeyPairSync, randomUUID, sign, type KeyObject } from "node:crypto";
import { createServer, type IncomingHttpHeaders, type Server } from "node:http";
import type { AddressInfo } from "node:net";

export const ISSUER = "https://auth.angler.test";
export const APP = "https://news.angler.test";
/** A fixed clock for the tests, in milliseconds. */
export const NOW = 1_800_000_000_000;

export type Alg = "EdDSA" | "ML-DSA-65";

export interface TestKey {
  kid: string;
  alg: Alg;
  privateKey: KeyObject;
  publicKey: KeyObject;
  /** The JWK as the service publishes it in its JWKS. */
  jwk: Record<string, unknown>;
}

export function mlDsaSupported(): boolean {
  try {
    generateKeyPairSync("ml-dsa-65" as "ed25519");
    return true;
  } catch {
    return false;
  }
}

export function newKey(alg: Alg = "EdDSA", kid: string = randomUUID()): TestKey {
  const { publicKey, privateKey } = generateKeyPairSync((alg === "EdDSA" ? "ed25519" : "ml-dsa-65") as "ed25519");
  return { kid, alg, privateKey, publicKey, jwk: { ...publicKey.export({ format: "jwk" }), kid, alg, use: "sig" } };
}

export function claims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const iat = NOW / 1000;
  return {
    iss: ISSUER,
    aud: "authenticated",
    iat,
    nbf: iat - 5,
    exp: iat + 600,
    jti: randomUUID(),
    sub: "6f1f3d7e-2f8e-4b0e-9a8e-0d6a2c1f4b11",
    sid: "a".repeat(32),
    role: "authenticated",
    email: "ada@example.com",
    email_verified: true,
    amr: ["password"],
    aal: "aal1",
    policy: "strict",
    wallet_address: null,
    ...overrides,
  };
}

const b64 = (value: unknown) => Buffer.from(typeof value === "string" ? value : JSON.stringify(value)).toString("base64url");

export interface MintOptions {
  header?: Record<string, unknown>;
  /** Sign with this key instead of `key`: a forged token that claims `key`'s kid. */
  signWith?: KeyObject;
}

/** A compact JWS the way the service builds one. */
export function mint(key: TestKey, payload: Record<string, unknown> = claims(), options: MintOptions = {}): string {
  const header = { alg: key.alg, typ: "JWT", kid: key.kid, ...options.header };
  const input = `${b64(header)}.${b64(payload)}`;
  return `${input}.${sign(null, Buffer.from(input), options.signWith ?? key.privateKey).toString("base64url")}`;
}

/** An HS256 token whose secret is the bytes of a public key: the classic algorithm-confusion forgery. */
export function mintHs256(secret: Buffer, kid: string, payload: Record<string, unknown> = claims()): string {
  const input = `${b64({ alg: "HS256", typ: "JWT", kid })}.${b64(payload)}`;
  return `${input}.${createHmac("sha256", secret).update(input).digest("base64url")}`;
}

export function publicKeyBytes(key: TestKey): Buffer {
  return key.publicKey.export({ format: "der", type: "spki" });
}

export interface Recorded {
  method: string;
  path: string;
  headers: IncomingHttpHeaders;
  body: Record<string, unknown> | null;
}

export interface Reply {
  status?: number;
  body?: unknown;
  headers?: Record<string, string>;
}

export type Route = (request: Recorded) => Reply | Promise<Reply>;

export interface FakeAuth {
  url: string;
  requests: Recorded[];
  /** The keys the JWKS lists. Replace the array to rotate. */
  jwks: { keys: Record<string, unknown>[]; status: number };
  on(route: string, handler: Route | Reply): void;
  count(route: string): number;
  close(): Promise<void>;
}

/** A stand-in for angler-auth on a loopback port: the JWKS plus whatever routes a test registers. */
export async function fakeAuth(): Promise<FakeAuth> {
  const requests: Recorded[] = [];
  const routes = new Map<string, Route>();
  const jwks: FakeAuth["jwks"] = { keys: [], status: 200 };

  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", async () => {
      const text = Buffer.concat(chunks).toString("utf8");
      const recorded: Recorded = { method: req.method ?? "GET", path: req.url ?? "/", headers: req.headers, body: text ? (JSON.parse(text) as Record<string, unknown>) : null };
      requests.push(recorded);
      const key = `${recorded.method} ${recorded.path.split("?")[0]}`;
      let reply: Reply;
      if (key === "GET /.well-known/jwks.json") reply = { status: jwks.status, body: jwks.status === 200 ? { keys: jwks.keys } : { error: "down" } };
      else reply = (await routes.get(key)?.(recorded)) ?? { status: 404, body: { error: "not_found" } };
      res.writeHead(reply.status ?? 200, { "content-type": "application/json", ...reply.headers });
      res.end(reply.body === undefined ? "" : typeof reply.body === "string" ? reply.body : JSON.stringify(reply.body));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;

  return {
    url: `http://127.0.0.1:${port}`,
    requests,
    jwks,
    on: (route, handler) => routes.set(route, typeof handler === "function" ? handler : () => handler),
    count: (route) => requests.filter((r) => `${r.method} ${r.path.split("?")[0]}` === route).length,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}
