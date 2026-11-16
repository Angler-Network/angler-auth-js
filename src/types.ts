/** How a session was opened; `amr` in the access token lists the same values. */
export type AuthMethod =
  | "password"
  | "email_otp"
  | "magic_link"
  | "google"
  | "discord"
  | "x"
  | "apple"
  | "wallet"
  | "solana"
  | "telegram"
  | "passkey"
  | "passkey_pq"
  | "totp"
  | "recovery_code";

export type OAuthProvider = "google" | "apple" | "discord" | "x";

export type Language = "en" | "tr";

/**
 * Claims of an access token (`POST /token`). Supabase/PostgREST compatible: `role` is
 * `authenticated` and `aud` is `JWT_AUDIENCE`.
 */
export interface AuthClaims {
  iss: string;
  aud: string | string[];
  sub: string;
  /** First 32 characters of the session id. */
  sid: string;
  role: string;
  email: string | null;
  email_verified: boolean;
  amr: AuthMethod[];
  aal: "aal1" | "aal2";
  policy: "strict" | "standard";
  /** Where the user deposits: the embedded wallet, else the wallet the account signed up with, else null. */
  wallet_address: string | null;
  iat: number;
  nbf: number;
  exp: number;
  jti: string;
  [claim: string]: unknown;
}

export interface WalletInfo {
  address: string;
  chainId: number;
  kind: "external" | "embedded";
  ownerPasskeyId?: string | null;
  deployed?: boolean;
  /** An embedded wallet owned by a sign-in passkey: never used for deposits, funds should move out. */
  legacy?: boolean;
}

export interface AccountInfo {
  id: string;
  email: string | null;
  emailVerified: boolean;
  name: string | null;
  image: string | null;
  hasPassword: boolean;
  totpEnabled: boolean;
  oauth: { provider: OAuthProvider; email: string | null }[];
  wallets: WalletInfo[];
  /** Solana wallets and Telegram accounts: `solana:<base58 public key>` and `telegram:<user id>`. */
  identities: { identity: string }[];
  passkeys: { id: string; name: string | null; createdAt: string; lastUsedAt: string | null }[];
}

export type SignInMethodKind = "email" | "password" | "oauth" | "wallet" | "solana" | "telegram" | "passkey";

/** One way into the account, from `listIdentities`. `id` is what `unlinkIdentity` takes. */
export interface SignInMethod {
  id: string;
  kind: SignInMethodKind;
  /** The provider, for `oauth`. */
  provider?: OAuthProvider;
  /** What to show: the address, the wallet address, a Telegram user, a passkey's name. */
  label: string;
  createdAt: string | null;
  /** Whether it can sign in right now, under the service's policy and settings. */
  canSignIn: boolean;
  /** Whether `unlinkIdentity` would remove it now: not the address, not a wallet's owner passkey, not the last way in. */
  removable: boolean;
  /** Why it can never be removed, when that is the reason. */
  locked?: "email" | "wallet_owner_passkey";
}
