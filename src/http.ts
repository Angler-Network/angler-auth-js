import { AuthError } from "./errors.ts";

export interface JsonRequest {
  method: "GET" | "POST";
  headers?: Record<string, string>;
  body?: unknown;
  credentials?: RequestCredentials;
  signal?: AbortSignal;
  cache?: RequestCache;
}

/** Joins a base URL (with or without a trailing slash) and an absolute path. */
export function joinUrl(base: string, path: string): string {
  return `${base.replace(/\/+$/, "")}${path}`;
}

function retryAfterOf(response: Response, body: Record<string, unknown>): number | undefined {
  if (typeof body.retryAfter === "number") return body.retryAfter;
  const header = Number(response.headers.get("retry-after"));
  return Number.isFinite(header) && header > 0 ? header : undefined;
}

/**
 * One JSON call. Resolves with the parsed body of a 2xx answer and throws an `AuthError` for everything
 * else: an error answer (`{ error: code, ... }`), a body that is not JSON, or no answer at all.
 */
export async function requestJson<T>(fetchImpl: typeof fetch, url: string, request: JsonRequest): Promise<T> {
  const headers: Record<string, string> = { accept: "application/json", ...request.headers };
  const init: RequestInit = { method: request.method, headers };
  if (request.credentials) init.credentials = request.credentials;
  if (request.signal) init.signal = request.signal;
  if (request.cache) init.cache = request.cache;
  if (request.method === "POST") {
    headers["content-type"] = "application/json";
    init.body = JSON.stringify(request.body ?? {});
  }

  let response: Response;
  try {
    response = await fetchImpl(url, init);
  } catch (cause) {
    if (cause instanceof Error && cause.name === "AbortError") throw cause;
    throw new AuthError({ status: 0, code: "network_error", cause });
  }

  const text = await response.text().catch(() => "");
  let body: Record<string, unknown> = {};
  if (text) {
    try {
      const parsed: unknown = JSON.parse(text);
      if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("not an object");
      body = parsed as Record<string, unknown>;
    } catch {
      throw new AuthError({ status: response.status, code: response.ok ? "invalid_response" : `http_${response.status}` });
    }
  }

  if (!response.ok) {
    const { error, retryAfter: _retryAfter, ...details } = body;
    const retryAfter = retryAfterOf(response, body);
    throw new AuthError({
      status: response.status,
      code: typeof error === "string" ? error : `http_${response.status}`,
      ...(retryAfter === undefined ? {} : { retryAfter }),
      details,
    });
  }
  return body as T;
}
