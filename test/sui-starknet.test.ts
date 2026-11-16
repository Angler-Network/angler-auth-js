import assert from "node:assert/strict";
import { after, before, beforeEach, describe, test } from "node:test";
import {
  AuthError,
  buildStarknetTypedData,
  buildSuiMessage,
  createAuthClient,
  normalizeStarknetAddress,
  normalizeSuiAddress,
  type AuthClient,
  type StarknetSigner,
  type StarknetTypedData,
  type SuiSigner,
} from "../src/client/index.ts";
import { fakeAuth, NOW, type FakeAuth } from "./fake-auth.ts";

let auth: FakeAuth;
let clock: number;

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

const NONCE = "0123456789abcdef0123456789abcdef";
const ISSUED_AT = "2027-01-15T08:00:00.000Z";
const ISSUED_SECONDS = 1_800_000_000;
const stop = { body: { status: "confirmation_required", confirmation: "email" } };
const page = { domain: "news.angler.test", uri: "https://news.angler.test" };

// --- Sui --------------------------------------------------------------------------------------

const SUI_ADDRESS = `0x${"ab".repeat(32)}`;
const SUI_SIGNATURE = Buffer.alloc(97, 3).toString("base64");

const suiWallet = (messages: string[], over: Partial<SuiSigner> = {}): SuiSigner => ({
  address: SUI_ADDRESS,
  ...page,
  signPersonalMessage: async (bytes) => (messages.push(new TextDecoder().decode(bytes)), SUI_SIGNATURE),
  ...over,
});

describe("Sign-In With Sui", () => {
  test("builds the message the service parses, has the wallet sign its bytes, and sends the wallet's own signature", async () => {
    auth.on("POST /sui/nonce", { body: { nonce: NONCE } });
    auth.on("POST /sui/verify", { body: { status: "signed_in", userId: "u" } });
    const messages: string[] = [];
    const result = await client().signInWithSui(suiWallet(messages));
    assert.equal(result.status, "signed_in");
    // Pinned on purpose: any change here has to be checked against the service's parseSuiMessage.
    assert.deepEqual(messages, [
      [
        "news.angler.test wants you to sign in with your Sui account:",
        SUI_ADDRESS,
        "",
        "Sign in to Angler.",
        "",
        "URI: https://news.angler.test",
        "Version: 1",
        "Chain ID: sui:mainnet",
        `Nonce: ${NONCE}`,
        `Issued At: ${ISSUED_AT}`,
      ].join("\n"),
    ]);
    assert.deepEqual(auth.requests.map((r) => r.path), ["/sui/nonce", "/sui/verify"]);
    assert.deepEqual(last()?.body, { message: messages[0], signature: SUI_SIGNATURE });
  });

  test("a wallet that answers with an object ({ bytes, signature }) works too", async () => {
    auth.on("POST /sui/nonce", { body: { nonce: NONCE } });
    auth.on("POST /sui/verify", { body: { status: "signed_in", userId: "u" } });
    await client().signInWithSui(suiWallet([], { signPersonalMessage: async () => ({ signature: SUI_SIGNATURE }) }));
    assert.equal((last()?.body as { signature: string }).signature, SUI_SIGNATURE);
  });

  test("a statement, a chain and an expiry are options; a missing page identity is an error", async () => {
    auth.on("POST /sui/nonce", { body: { nonce: NONCE } });
    auth.on("POST /sui/verify", { body: { status: "signed_in", userId: "u" } });
    const messages: string[] = [];
    await client().signInWithSui(suiWallet(messages, { statement: "Welcome.", chainId: "sui:testnet", expiresInSeconds: 300 }));
    assert.match(messages[0]!, /\n\nWelcome\.\n\nURI: /);
    assert.match(messages[0]!, /\nChain ID: sui:testnet\n/);
    assert.ok(messages[0]!.endsWith(`\nIssued At: ${ISSUED_AT}\nExpiration Time: 2027-01-15T08:05:00.000Z`));
    await assert.rejects(client().signInWithSui({ address: SUI_ADDRESS, signPersonalMessage: async () => SUI_SIGNATURE }), reject("missing_option"));
  });

  test("the address is written in the one form the service takes, and a bad one never reaches the wallet", async () => {
    auth.on("POST /sui/nonce", { body: { nonce: NONCE } });
    auth.on("POST /sui/verify", { body: { status: "signed_in", userId: "u" } });
    const messages: string[] = [];
    await client().signInWithSui(suiWallet(messages, { address: `0x${"AB".repeat(32)}` }));
    await client().signInWithSui(suiWallet(messages, { address: "0x2" }));
    assert.match(messages[0]!, new RegExp(`\n${SUI_ADDRESS}\n`));
    assert.match(messages[1]!, new RegExp(`\n0x${"0".repeat(63)}2\n`));
    assert.equal(normalizeSuiAddress("0xAbC"), `0x${"0".repeat(61)}abc`);
    auth.requests.length = 0;
    for (const address of ["", "0x", "ab".repeat(32), `0x${"a".repeat(65)}`, "0xzz", ` ${SUI_ADDRESS}`, `${SUI_ADDRESS}\n`]) {
      await assert.rejects(client().signInWithSui(suiWallet([], { address })), reject("invalid_message"), address);
    }
    assert.equal(auth.requests.length, 0);
  });

  test("a wallet that gives no signature, or the wrong kind of thing, is an error and nothing is sent to verify", async () => {
    auth.on("POST /sui/nonce", { body: { nonce: NONCE } });
    for (const bad of [undefined, null, "", 5, {}, { signature: 5 }, { signature: "" }]) {
      await assert.rejects(client().signInWithSui(suiWallet([], { signPersonalMessage: async () => bad as never })), reject("invalid_signature"));
    }
    assert.equal(auth.count("POST /sui/verify"), 0);
    await assert.rejects(client().signInWithSui(suiWallet([], { signPersonalMessage: async () => Promise.reject(new Error("User rejected")) })), /User rejected/);
  });

  test("linking sends link, asks for the emailed code, and resends the same message and signature with it", async () => {
    auth.on("POST /sui/nonce", { body: { nonce: NONCE } });
    let calls = 0;
    auth.on("POST /sui/verify", () => (++calls === 1 ? stop : { body: { status: "linked", identity: `sui:${SUI_ADDRESS}` } }));
    const messages: string[] = [];
    const result = await client().linkSui(suiWallet(messages), { getConfirmationCode: () => "012345" });
    assert.deepEqual(result, { status: "linked", identity: `sui:${SUI_ADDRESS}` });
    assert.equal(auth.count("POST /sui/nonce"), 1);
    assert.equal(messages.length, 1);
    const [first, second] = auth.requests.filter((r) => r.path === "/sui/verify");
    assert.deepEqual(first?.body, { message: messages[0], signature: SUI_SIGNATURE, link: true });
    assert.deepEqual(second?.body, { message: messages[0], signature: SUI_SIGNATURE, link: true, code: "012345" });
  });

  test("without a way to ask for the code it is an error, and a service that keeps asking is not looped on", async () => {
    auth.on("POST /sui/nonce", { body: { nonce: NONCE } });
    auth.on("POST /sui/verify", stop);
    await assert.rejects(client().linkSui(suiWallet([])), reject("confirmation_required"));
    assert.equal(auth.count("POST /sui/verify"), 1);
    auth.requests.length = 0;
    await assert.rejects(client().linkSui(suiWallet([]), { getConfirmationCode: () => "000000" }), reject("confirmation_required"));
    assert.equal(auth.count("POST /sui/verify"), 2);
  });

  test("the service's refusals are typed, with the scheme it named", async () => {
    auth.on("POST /sui/nonce", { body: { nonce: NONCE } });
    auth.on("POST /sui/verify", { status: 400, body: { error: "unsupported_signature", scheme: "zklogin" } });
    await assert.rejects(client().signInWithSui(suiWallet([])), (error: unknown) => reject("unsupported_signature", 400)(error) && (error as AuthError).details.scheme === "zklogin");
    auth.on("POST /sui/verify", { status: 401, body: { error: "invalid_nonce" } });
    await assert.rejects(client().signInWithSui(suiWallet([])), reject("invalid_nonce", 401));
    auth.on("POST /sui/verify", { status: 409, body: { error: "already_linked" } });
    await assert.rejects(client().linkSui(suiWallet([]), { getConfirmationCode: () => "1" }), reject("already_linked", 409));
  });

  test("a new nonce comes from /sui/nonce, and the message builder writes the layout the service parses", async () => {
    auth.on("POST /sui/nonce", { body: { nonce: NONCE } });
    assert.deepEqual(await client().suiNonce(), { nonce: NONCE });
    assert.equal(
      buildSuiMessage({ domain: "d.test", address: SUI_ADDRESS, uri: "https://d.test", chainId: "sui:mainnet", nonce: NONCE, issuedAt: ISSUED_AT, statement: "Hi" }),
      `d.test wants you to sign in with your Sui account:\n${SUI_ADDRESS}\n\nHi\n\nURI: https://d.test\nVersion: 1\nChain ID: sui:mainnet\nNonce: ${NONCE}\nIssued At: ${ISSUED_AT}`,
    );
  });
});

// --- Starknet ---------------------------------------------------------------------------------

const STARKNET_ADDRESS = `0x${"0".repeat(8)}${"12ab".repeat(14)}`;
const STARKNET_SIGNATURE = ["0x1111", "0x2222"];

const starknetWallet = (typedData: StarknetTypedData[], over: Partial<StarknetSigner> = {}): StarknetSigner => ({
  address: STARKNET_ADDRESS,
  ...page,
  signTypedData: async (data) => (typedData.push(data), STARKNET_SIGNATURE),
  ...over,
});

describe("Sign-In With Starknet", () => {
  test("builds the typed data the service reads, has the wallet sign it, and sends it with the signature", async () => {
    auth.on("POST /starknet/nonce", { body: { nonce: NONCE } });
    auth.on("POST /starknet/verify", { body: { status: "signed_in", userId: "u" } });
    const seen: StarknetTypedData[] = [];
    const result = await client().signInWithStarknet(starknetWallet(seen));
    assert.equal(result.status, "signed_in");
    // Pinned on purpose: any change here has to be checked against the service's parseStarknetTypedData and its hash.
    assert.deepEqual(seen, [
      {
        types: {
          StarknetDomain: [
            { name: "name", type: "shortstring" },
            { name: "version", type: "shortstring" },
            { name: "chainId", type: "shortstring" },
            { name: "revision", type: "shortstring" },
          ],
          Message: [
            { name: "address", type: "ContractAddress" },
            { name: "host", type: "string" },
            { name: "uri", type: "string" },
            { name: "statement", type: "string" },
            { name: "nonce", type: "felt" },
            { name: "issuedAt", type: "timestamp" },
            { name: "expirationTime", type: "timestamp" },
          ],
        },
        primaryType: "Message",
        domain: { name: "Angler", version: "v1", chainId: "SN_MAIN", revision: "1" },
        message: {
          address: STARKNET_ADDRESS,
          host: "news.angler.test",
          uri: "https://news.angler.test",
          statement: "Sign in to Angler.",
          nonce: `0x${NONCE}`,
          issuedAt: String(ISSUED_SECONDS),
          expirationTime: String(ISSUED_SECONDS + 600),
        },
      },
    ]);
    assert.deepEqual(auth.requests.map((r) => r.path), ["/starknet/nonce", "/starknet/verify"]);
    assert.deepEqual(last()?.body, { typedData: seen[0], signature: STARKNET_SIGNATURE });
  });

  test("a statement, a chain and a lifetime are options; a missing page identity is an error", async () => {
    auth.on("POST /starknet/nonce", { body: { nonce: NONCE } });
    auth.on("POST /starknet/verify", { body: { status: "signed_in", userId: "u" } });
    const seen: StarknetTypedData[] = [];
    await client().signInWithStarknet(starknetWallet(seen, { statement: "Welcome.", chainId: "SN_SEPOLIA", expiresInSeconds: 300 }));
    assert.equal(seen[0]?.message.statement, "Welcome.");
    assert.equal(seen[0]?.domain.chainId, "SN_SEPOLIA");
    assert.equal(seen[0]?.message.expirationTime, String(ISSUED_SECONDS + 300));
    await assert.rejects(client().signInWithStarknet({ address: STARKNET_ADDRESS, signTypedData: async () => STARKNET_SIGNATURE }), reject("missing_option"));
  });

  test("the address is written in the one form the service takes, and a bad one never reaches the wallet", async () => {
    auth.on("POST /starknet/nonce", { body: { nonce: NONCE } });
    auth.on("POST /starknet/verify", { body: { status: "signed_in", userId: "u" } });
    const seen: StarknetTypedData[] = [];
    await client().signInWithStarknet(starknetWallet(seen, { address: "0x123ABC" }));
    assert.equal(seen[0]?.message.address, `0x${"0".repeat(58)}123abc`);
    assert.equal(normalizeStarknetAddress(`0x${"F".repeat(2)}`), `0x${"0".repeat(62)}ff`);
    auth.requests.length = 0;
    for (const address of ["", "0x", "0x0", `0x${"0".repeat(64)}`, "12ab", `0x${"a".repeat(65)}`, `0x${"f".repeat(64)}`, `0x0${"f".repeat(63)}`, "0xzz", ` 0x1`]) {
      await assert.rejects(client().signInWithStarknet(starknetWallet([], { address })), reject("invalid_message"), address);
    }
    assert.equal(auth.requests.length, 0);
  });

  test("a wallet that gives no felts, or the wrong kind of thing, is an error and nothing is sent to verify", async () => {
    auth.on("POST /starknet/nonce", { body: { nonce: NONCE } });
    for (const bad of [undefined, null, "0x1", [], [1, 2], { r: "0x1", s: "0x2" }]) {
      await assert.rejects(client().signInWithStarknet(starknetWallet([], { signTypedData: async () => bad as never })), reject("invalid_signature"));
    }
    assert.equal(auth.count("POST /starknet/verify"), 0);
  });

  test("linking sends link, asks for the emailed code, and resends the same typed data and signature with it", async () => {
    auth.on("POST /starknet/nonce", { body: { nonce: NONCE } });
    let calls = 0;
    auth.on("POST /starknet/verify", () => (++calls === 1 ? stop : { body: { status: "linked", identity: `starknet:${STARKNET_ADDRESS}` } }));
    const seen: StarknetTypedData[] = [];
    const result = await client().linkStarknet(starknetWallet(seen), { getConfirmationCode: () => "012345" });
    assert.deepEqual(result, { status: "linked", identity: `starknet:${STARKNET_ADDRESS}` });
    assert.equal(auth.count("POST /starknet/nonce"), 1);
    assert.equal(seen.length, 1);
    const [first, second] = auth.requests.filter((r) => r.path === "/starknet/verify");
    assert.deepEqual(first?.body, { typedData: seen[0], signature: STARKNET_SIGNATURE, link: true });
    assert.deepEqual(second?.body, { typedData: seen[0], signature: STARKNET_SIGNATURE, link: true, code: "012345" });
    auth.on("POST /starknet/verify", stop);
    await assert.rejects(client().linkStarknet(starknetWallet([])), reject("confirmation_required"));
  });

  test("a node that did not answer is a typed error to try again; other refusals are typed too", async () => {
    auth.on("POST /starknet/nonce", { body: { nonce: NONCE } });
    auth.on("POST /starknet/verify", { status: 503, body: { error: "wallet_check_unavailable" } });
    await assert.rejects(client().signInWithStarknet(starknetWallet([])), reject("wallet_check_unavailable", 503));
    auth.on("POST /starknet/verify", { status: 401, body: { error: "invalid_signature" } });
    await assert.rejects(client().signInWithStarknet(starknetWallet([])), reject("invalid_signature", 401));
    auth.on("POST /starknet/nonce", { status: 404, body: { error: "not_found" } });
    await assert.rejects(client().starknetNonce(), reject("not_found", 404));
  });

  test("suiEnabled reads /providers; an older service that does not list it is off", async () => {
    auth.on("GET /providers", { body: { oauth: [], telegram: false, sui: true, starknet: false } });
    assert.equal(await client().suiEnabled(), true);
    assert.equal(await client().starknetEnabled(), false);
    auth.on("GET /providers", { body: { oauth: [], telegram: false } });
    assert.equal(await client().suiEnabled(), false);
  });

  test("a method of a kind the SDK does not know is listed as it comes", async () => {
    auth.on("GET /identities", { body: { methods: [{ id: "future:abc", kind: "unknown", label: "abc", createdAt: null, canSignIn: false, removable: true }], confirmation: "none" } });
    const { methods } = await client().listIdentities();
    assert.deepEqual(methods.map((m) => [m.kind, m.canSignIn]), [["unknown", false]]);
  });

  test("starknetEnabled reads /providers, and the builder is the one the service reads", async () => {
    auth.on("GET /providers", { body: { oauth: [], telegram: false, starknet: true } });
    assert.equal(await client().starknetEnabled(), true);
    auth.on("GET /providers", { body: { oauth: [], telegram: false } });
    assert.equal(await client().starknetEnabled(), false);
    const data = buildStarknetTypedData({ address: STARKNET_ADDRESS, chainId: "SN_MAIN", host: "d.test", uri: "https://d.test", nonce: NONCE, issuedAt: 1, expirationTime: 2 });
    assert.equal(data.message.statement, "Sign in to Angler.");
    assert.equal(data.message.nonce, `0x${NONCE}`);
  });
});
