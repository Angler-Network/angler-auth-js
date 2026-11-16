import { AuthError } from "../errors.ts";

/** The SNIP-12 (revision 1) typed data angler-auth reads. The service refuses any other types, domain or key. */
export interface StarknetTypedData {
  types: {
    StarknetDomain: { name: string; type: string }[];
    Message: { name: string; type: string }[];
  };
  primaryType: "Message";
  domain: { name: "Angler"; version: "v1"; chainId: string; revision: "1" };
  message: {
    address: string;
    host: string;
    uri: string;
    statement: string;
    nonce: string;
    issuedAt: string;
    expirationTime: string;
  };
}

export interface StarknetMessageInput {
  /** The account, `0x` and 64 lower-case hex digits (`normalizeStarknetAddress` makes it). */
  address: string;
  /** `SN_MAIN`. Must be one of the chains the service has a node for (`STARKNET_RPC_URLS`). */
  chainId: string;
  /** Host (with port) the user is on. Must be the auth host or one of the service's allowed origins. */
  host: string;
  /** Must be one of the service's allowed origins. */
  uri: string;
  statement?: string;
  /** From `starknetNonce`: 32 hex digits. */
  nonce: string;
  /** Unix seconds. */
  issuedAt: number;
  /** Unix seconds, after `issuedAt` and at most an hour later. */
  expirationTime: number;
}

export const DEFAULT_STARKNET_STATEMENT = "Sign in to Angler.";
export const DEFAULT_STARKNET_CHAIN = "SN_MAIN";

/** A felt is below 2^251 + 17 * 2^192 + 1; a contract address is below 2^251 - 256. */
const ADDRESS_BOUND = 2n ** 251n - 256n;

/**
 * A Starknet address in the one form the service takes: `0x` and 64 lower-case hex digits. Wallets give shortened forms
 * (`0x123...`) and some upper-case; both are padded and lower-cased. A value that is not a contract address is an error.
 */
export function normalizeStarknetAddress(address: string): string {
  const fail = () => new AuthError({ status: 0, code: "invalid_message", details: { reason: "address" } });
  if (!/^0x[0-9a-fA-F]{1,64}$/.test(address)) throw fail();
  const value = BigInt(address);
  if (value === 0n || value >= ADDRESS_BOUND) throw fail();
  return `0x${address.slice(2).toLowerCase().padStart(64, "0")}`;
}

/** The typed message a Starknet wallet signs with `wallet_signTypedData`. The wallet shows every field to the person. */
export function buildStarknetTypedData(input: StarknetMessageInput): StarknetTypedData {
  return {
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
    domain: { name: "Angler", version: "v1", chainId: input.chainId, revision: "1" },
    message: {
      address: input.address,
      host: input.host,
      uri: input.uri,
      statement: input.statement ?? DEFAULT_STARKNET_STATEMENT,
      nonce: `0x${input.nonce}`,
      issuedAt: String(input.issuedAt),
      expirationTime: String(input.expirationTime),
    },
  };
}
