const ALPHABET = /^[A-Za-z0-9_-]*$/;

export function base64urlEncode(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = "";
  for (let i = 0; i < view.length; i += 0x8000) binary += String.fromCharCode(...view.subarray(i, i + 0x8000));
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

/** Strict: only the base64url alphabet, no padding, no whitespace. Throws on anything else. */
export function base64urlDecode(text: string): Uint8Array<ArrayBuffer> {
  if (!ALPHABET.test(text) || text.length % 4 === 1) throw new TypeError("invalid base64url");
  const binary = atob(text.replaceAll("-", "+").replaceAll("_", "/"));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** The JSON object in one part of a JWT (header or payload), or null. The signature is not looked at. */
export function decodeJwtPart(part: string): Record<string, unknown> | null {
  try {
    const value: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(base64urlDecode(part)));
    return value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}
