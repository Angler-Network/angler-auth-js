import { AuthError } from "../errors.ts";

export interface SiweMessageInput {
  /** Host (with port) the user is on. Must be the auth host or one of the service's allowed origins. */
  domain: string;
  /** EIP-55 checksummed or all-lowercase address. */
  address: string;
  /** Must be one of the service's allowed origins. */
  uri: string;
  chainId: number;
  nonce: string;
  issuedAt: string;
  statement?: string;
  expirationTime?: string;
}

export const DEFAULT_SIWE_STATEMENT = "Sign in to Angler.";

/**
 * An EIP-4361 message in the exact shape angler-auth's strict parser takes. A statement is always
 * written: the service rejects the statement-less layout (two blank lines).
 */
export function buildSiweMessage(input: SiweMessageInput): string {
  const lines = [
    `${input.domain} wants you to sign in with your Ethereum account:`,
    input.address,
    "",
    input.statement ?? DEFAULT_SIWE_STATEMENT,
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

/** `domain` and `uri` of the page the code runs on. */
export function pageIdentity(): { domain: string; uri: string } {
  if (typeof location === "undefined") throw new AuthError({ status: 0, code: "missing_option", details: { field: "domain" } });
  return { domain: location.host, uri: location.origin };
}
