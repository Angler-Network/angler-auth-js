import { base64urlDecode, base64urlEncode } from "../base64url.ts";
import { AuthError } from "../errors.ts";

/** What `/passkey/register/options` answers: a WebAuthn dictionary whose binary fields are base64url strings. */
export interface RegistrationOptionsJson {
  challenge: string;
  rp: { id: string; name: string };
  user: { id: string; name: string; displayName: string };
  pubKeyCredParams: { type: "public-key"; alg: number }[];
  timeout: number;
  attestation: "none";
  authenticatorSelection: { residentKey: "required"; requireResidentKey: true; userVerification: "required" };
  excludeCredentials: { type: "public-key"; id: string; transports?: string[] }[];
  /** `email`: a code was emailed and `/passkey/register/verify` needs it. */
  confirmation: "email" | "none";
}

/** What `/passkey/login/options` and `/mfa/passkey/options` answer. */
export interface RequestOptionsJson {
  challenge: string;
  rpId: string;
  timeout: number;
  userVerification: "required";
  allowCredentials: { type: "public-key"; id: string; transports?: string[] }[];
}

export interface RegistrationCredentialJson {
  id: string;
  rawId: string;
  type: string;
  response: { clientDataJSON: string; attestationObject: string; transports: string[] };
}

export interface AssertionCredentialJson {
  id: string;
  rawId: string;
  type: string;
  response: { clientDataJSON: string; authenticatorData: string; signature: string; userHandle?: string };
}

type Descriptor = { type: "public-key"; id: string; transports?: string[] };

function descriptor(item: Descriptor): PublicKeyCredentialDescriptor {
  return {
    type: item.type,
    id: base64urlDecode(item.id),
    ...(item.transports ? { transports: item.transports as AuthenticatorTransport[] } : {}),
  };
}

export function creationOptions(json: RegistrationOptionsJson): PublicKeyCredentialCreationOptions {
  return {
    challenge: base64urlDecode(json.challenge),
    rp: json.rp,
    user: { id: base64urlDecode(json.user.id), name: json.user.name, displayName: json.user.displayName },
    pubKeyCredParams: json.pubKeyCredParams,
    timeout: json.timeout,
    attestation: json.attestation,
    authenticatorSelection: json.authenticatorSelection,
    excludeCredentials: json.excludeCredentials.map(descriptor),
  };
}

export function requestOptions(json: RequestOptionsJson): PublicKeyCredentialRequestOptions {
  return {
    challenge: base64urlDecode(json.challenge),
    rpId: json.rpId,
    timeout: json.timeout,
    userVerification: json.userVerification,
    allowCredentials: json.allowCredentials.map(descriptor),
  };
}

export function registrationJson(credential: PublicKeyCredential): RegistrationCredentialJson {
  const response = credential.response as AuthenticatorAttestationResponse;
  return {
    id: credential.id,
    rawId: base64urlEncode(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: base64urlEncode(response.clientDataJSON),
      attestationObject: base64urlEncode(response.attestationObject),
      // The service stores these so a later sign-in can hint the authenticator.
      transports: response.getTransports?.() ?? [],
    },
  };
}

export function assertionJson(credential: PublicKeyCredential): AssertionCredentialJson {
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: credential.id,
    rawId: base64urlEncode(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: base64urlEncode(response.clientDataJSON),
      authenticatorData: base64urlEncode(response.authenticatorData),
      signature: base64urlEncode(response.signature),
      ...(response.userHandle && response.userHandle.byteLength > 0 ? { userHandle: base64urlEncode(response.userHandle) } : {}),
    },
  };
}

export function credentialsContainer(injected?: CredentialsContainer): CredentialsContainer {
  const container = injected ?? (typeof navigator === "undefined" ? undefined : navigator.credentials);
  if (!container) throw new AuthError({ status: 0, code: "passkeys_unsupported" });
  return container;
}

/** Runs a `credentials.create` / `credentials.get` call, turning a dismissed prompt into a typed error. */
export async function prompt(run: () => Promise<Credential | null>): Promise<PublicKeyCredential> {
  let credential: Credential | null;
  try {
    credential = await run();
  } catch (cause) {
    if (cause instanceof Error && (cause.name === "NotAllowedError" || cause.name === "AbortError")) {
      throw new AuthError({ status: 0, code: "passkey_cancelled", cause });
    }
    throw cause;
  }
  if (!credential) throw new AuthError({ status: 0, code: "passkey_cancelled" });
  return credential as PublicKeyCredential;
}
