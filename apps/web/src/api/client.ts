/**
 * Thin fetch wrapper: prefixes VITE_API_BASE_URL (default: same origin, so the Vite dev proxy
 * forwards /api), attaches `Authorization: Bearer <token>` to every request, and reports 401s
 * to the auth layer (which clears the session and sends the user to /login).
 */

export const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/+$/, '');

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly details?: unknown,
    /** The parsed JSON error body, for endpoints that explain errors with extra fields. */
    readonly body?: Record<string, unknown>,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

let token: string | null = null;
let onUnauthorized: (() => void) | null = null;

export function setAuthToken(next: string | null): void {
  token = next;
}

export function getAuthToken(): string | null {
  return token;
}

/** Called once by the AuthProvider; invoked on any 401 from an authenticated request. */
export function setUnauthorizedHandler(handler: (() => void) | null): void {
  onUnauthorized = handler;
}

export function apiUrl(path: string): string {
  return `${API_BASE_URL}${path}`;
}

export function authHeaders(): Record<string, string> {
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function errorFrom(res: Response): Promise<ApiError> {
  let message = `Request failed (${res.status})`;
  let details: unknown;
  let body: Record<string, unknown> | undefined;
  try {
    const parsed = (await res.json()) as { error?: string; details?: unknown } | null;
    if (parsed && typeof parsed === 'object') {
      body = parsed as Record<string, unknown>;
      if (typeof parsed.error === 'string') message = parsed.error;
      details = parsed.details;
    }
  } catch {
    // Non-JSON error body; keep the generic message.
  }
  return new ApiError(res.status, message, details, body);
}

/** Shared 401 handling: a rejected token ends the session (except on the login call itself). */
export function handleUnauthorized(status: number): void {
  if (status === 401 && token) onUnauthorized?.();
}

export async function apiFetch(path: string, init: RequestInit = {}): Promise<Response> {
  let res: Response;
  try {
    res = await fetch(apiUrl(path), {
      ...init,
      headers: { ...authHeaders(), ...(init.headers as Record<string, string> | undefined) },
    });
  } catch {
    throw new ApiError(0, 'Cannot reach the WebGuard API. Check that it is running.');
  }
  if (!res.ok) {
    handleUnauthorized(res.status);
    throw await errorFrom(res);
  }
  return res;
}

export async function apiJson<T>(
  path: string,
  init: RequestInit & { json?: unknown } = {},
): Promise<T> {
  const { json, ...rest } = init;
  const res = await apiFetch(path, {
    ...rest,
    ...(json !== undefined
      ? {
          body: JSON.stringify(json),
          headers: {
            'Content-Type': 'application/json',
            ...(rest.headers as Record<string, string>),
          },
        }
      : {}),
  });
  if (res.status === 204) return undefined as T;
  const type = res.headers.get('content-type') ?? '';
  return (type.includes('application/json') ? await res.json() : await res.text()) as T;
}
