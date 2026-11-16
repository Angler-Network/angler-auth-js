import { AuthError } from "../errors.ts";
import { joinUrl, requestJson } from "../http.ts";
import type { AccountInfo } from "../types.ts";

export interface AdminClientOptions {
  /** The auth service, e.g. `https://auth.angler.network`. */
  authUrl: string;
  /** The service's `ADMIN_API_KEY`. Server side only: never in a browser bundle. */
  apiKey: string;
  /** Names the admin in the service's audit log (`X-Admin-Id`). */
  adminId?: string;
  fetch?: typeof fetch;
  /** Default 5000. */
  timeoutMs?: number;
}

export interface AdminUser {
  id: string;
  email: string | null;
  emailVerified: boolean;
  name: string | null;
  bannedAt: string | null;
  banReason: string | null;
  createdAt: string;
  lastSignInAt: string | null;
}

export interface AdminUserDetail extends AdminUser {
  /** Sign-in methods, wallets and passkeys: what `/session` describes. */
  account: AccountInfo | null;
}

export interface AdminUserPage {
  users: AdminUser[];
  total: number;
  page: number;
  perPage: number;
}

export interface AdminClient {
  /** Newest first. `query` matches email, name or an id prefix. `perPage` is at most 100. */
  listUsers(options?: { query?: string; page?: number; perPage?: number }): Promise<AdminUserPage>;
  getUser(id: string): Promise<AdminUserDetail>;
  /** Ends every session of the user at once. */
  banUser(id: string, reason?: string): Promise<{ status: "banned" }>;
  unbanUser(id: string): Promise<{ status: "unbanned" }>;
  /** Refused with `has_embedded_wallet` (409) for an account that holds one. */
  deleteUser(id: string): Promise<{ status: "deleted" }>;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function userPath(id: string): string {
  if (!UUID.test(id)) throw new AuthError({ status: 0, code: "invalid_input", details: { field: "id" } });
  return `/admin/users/${id}`;
}

export function createAdminClient(options: AdminClientOptions): AdminClient {
  const fetchImpl: typeof fetch = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
  const headers: Record<string, string> = { authorization: `Bearer ${options.apiKey}` };
  if (options.adminId) headers["x-admin-id"] = options.adminId;

  const call = <T>(method: "GET" | "POST", path: string, body?: unknown) =>
    requestJson<T>(fetchImpl, joinUrl(options.authUrl, path), {
      method,
      headers,
      body,
      signal: AbortSignal.timeout(options.timeoutMs ?? 5000),
      cache: "no-store",
    });

  return {
    listUsers(opts = {}) {
      const params = new URLSearchParams();
      if (opts.query) params.set("query", opts.query);
      if (opts.page !== undefined) params.set("page", String(opts.page));
      if (opts.perPage !== undefined) params.set("perPage", String(opts.perPage));
      const query = params.toString();
      return call("GET", `/admin/users${query ? `?${query}` : ""}`);
    },
    async getUser(id) {
      return (await call<{ user: AdminUserDetail }>("GET", userPath(id))).user;
    },
    banUser: (id, reason) => call("POST", `${userPath(id)}/ban`, { banned: true, ...(reason ? { reason } : {}) }),
    unbanUser: (id) => call("POST", `${userPath(id)}/ban`, { banned: false }),
    deleteUser: (id) => call("POST", `${userPath(id)}/delete`),
  };
}
