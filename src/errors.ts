/**
 * Codes the service answers with (`{ "error": "<code>" }`) plus the ones the SDK raises itself
 * (`status` 0: the request never got an answer).
 */
export type AuthErrorCode =
  | "unauthenticated"
  | "mfa_required"
  | "reauthentication_required"
  | "second_factor_required"
  | "email_not_verified"
  | "account_disabled"
  | "invalid_credentials"
  | "invalid_input"
  | "invalid_email"
  | "invalid_code"
  | "invalid_origin"
  | "invalid_credential"
  | "invalid_challenge"
  | "invalid_message"
  | "invalid_signature"
  | "invalid_nonce"
  | "expired_auth"
  | "auth_replayed"
  | "already_linked"
  | "invalid_admin_key"
  | "captcha_required"
  | "captcha_failed"
  | "captcha_unavailable"
  | "rate_limited"
  | "busy"
  | "not_found"
  | "last_sign_in_method"
  | "email_not_removable"
  | "wallet_owner_passkey"
  | "embedded_wallet_sign_in"
  | "unsupported_signature"
  | "wallet_check_unavailable"
  | "has_embedded_wallet"
  | "network_error"
  | "invalid_response"
  | "passkey_cancelled"
  | "passkeys_unsupported"
  | "confirmation_required"
  | "missing_option"
  | (string & {});

export interface AuthErrorInit {
  status: number;
  code: AuthErrorCode;
  /** Seconds to wait, from a `429`'s `Retry-After` header or `retryAfter` field. */
  retryAfter?: number;
  /** Every other field of the error body, e.g. `field` (`invalid_input`) or `reason` (`invalid_message`). */
  details?: Record<string, unknown>;
  cause?: unknown;
}

/** Every failed call to angler-auth. `status` is the HTTP status, or 0 when there was no answer. */
export class AuthError extends Error {
  readonly status: number;
  readonly code: AuthErrorCode;
  readonly retryAfter: number | undefined;
  readonly details: Record<string, unknown>;

  constructor(init: AuthErrorInit) {
    super(init.code, init.cause === undefined ? undefined : { cause: init.cause });
    this.name = "AuthError";
    this.status = init.status;
    this.code = init.code;
    this.retryAfter = init.retryAfter;
    this.details = init.details ?? {};
  }
}

export function isAuthError(error: unknown, code?: AuthErrorCode): error is AuthError {
  return error instanceof AuthError && (code === undefined || error.code === code);
}
