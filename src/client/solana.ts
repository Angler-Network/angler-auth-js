export interface SiwsMessageInput {
  /** Host (with port) the user is on. Must be the auth host or one of the service's allowed origins. */
  domain: string;
  /** The wallet's public key, base58. */
  address: string;
  /** Must be one of the service's allowed origins. */
  uri: string;
  /** `mainnet` for Wallet Standard wallets. Must be one of the service's `SOLANA_CHAIN_IDS`. */
  chainId: string;
  nonce: string;
  issuedAt: string;
  statement?: string;
  expirationTime?: string;
}

export const DEFAULT_SIWS_STATEMENT = "Sign in to Angler.";

/**
 * A Sign-In With Solana (CAIP-122) message in the text form Wallet Standard's `solana:signIn` makes, which is what
 * angler-auth's strict parser takes. A statement is always written.
 */
export function buildSiwsMessage(input: SiwsMessageInput): string {
  const lines = [
    `${input.domain} wants you to sign in with your Solana account:`,
    input.address,
    "",
    input.statement ?? DEFAULT_SIWS_STATEMENT,
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
