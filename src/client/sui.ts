import { AuthError } from "../errors.ts";

export interface SuiMessageInput {
  /** Host (with port) the user is on. Must be the auth host or one of the service's allowed origins. */
  domain: string;
  /** The account, `0x` and 64 lower-case hex digits (`normalizeSuiAddress` makes it). */
  address: string;
  /** Must be one of the service's allowed origins. */
  uri: string;
  /** `sui:mainnet`. Must be one of the service's `SUI_CHAIN_IDS`. */
  chainId: string;
  nonce: string;
  issuedAt: string;
  statement?: string;
  expirationTime?: string;
}

export const DEFAULT_SUI_STATEMENT = "Sign in to Angler.";
export const DEFAULT_SUI_CHAIN = "sui:mainnet";

/**
 * A Sui address in the one form the service takes: `0x` and 64 lower-case hex digits. Wallets give that already; a
 * shortened address (`0x2`) is padded. Anything that is not hex, or longer than 32 bytes, is an error.
 */
export function normalizeSuiAddress(address: string): string {
  if (!/^0x[0-9a-fA-F]{1,64}$/.test(address)) throw new AuthError({ status: 0, code: "invalid_message", details: { reason: "address" } });
  return `0x${address.slice(2).toLowerCase().padStart(64, "0")}`;
}

/**
 * A Sign-In With Sui message: the CAIP-122 layout of Sign-In With Solana, with "Sui account" in the header, which is what
 * angler-auth's strict parser takes. A statement is always written. The wallet signs its UTF-8 bytes as a personal message.
 */
export function buildSuiMessage(input: SuiMessageInput): string {
  const lines = [
    `${input.domain} wants you to sign in with your Sui account:`,
    input.address,
    "",
    input.statement ?? DEFAULT_SUI_STATEMENT,
    "",
    `URI: ${input.uri}`,
    "Version: 1",
    `Chain ID: ${input.chainId}`,
    `Nonce: ${input.nonce}`,
    `Issued At: ${input.issuedAt}`,
  ];
  if (input.expirationTime) lines.push(`Expiration Time: ${input.expirationTime}`);
  return lines.join("\n");
}
