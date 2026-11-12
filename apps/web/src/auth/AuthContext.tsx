import { useQueryClient } from '@tanstack/react-query';
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';
import { setAuthToken, setUnauthorizedHandler } from '../api/client';
import { api, type User } from '../api/endpoints';

export const TOKEN_STORAGE_KEY = 'webguard.token';

type AuthStatus = 'restoring' | 'authenticated' | 'anonymous';

interface AuthState {
  status: AuthStatus;
  user: User | null;
  /** Set when the session ended because the API rejected the token. */
  expired: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthState | null>(null);

function readStoredToken(): string | null {
  try {
    return window.localStorage.getItem(TOKEN_STORAGE_KEY);
  } catch {
    return null;
  }
}

function writeStoredToken(token: string | null): void {
  try {
    if (token) window.localStorage.setItem(TOKEN_STORAGE_KEY, token);
    else window.localStorage.removeItem(TOKEN_STORAGE_KEY);
  } catch {
    // Storage blocked (private mode): the session simply won't survive a reload.
  }
}

/** `exp` from a JWT payload (seconds), without verifying — only to skip obviously stale tokens. */
function tokenExpiry(token: string): number | null {
  try {
    const payload = JSON.parse(atob(token.split('.')[1]!.replace(/-/g, '+').replace(/_/g, '/')));
    return typeof payload.exp === 'number' ? payload.exp : null;
  } catch {
    return null;
  }
}

/**
 * The JWT lives in memory (`api/client`) and is mirrored to localStorage so a reload restores
 * the session. On start-up a stored token is validated with GET /api/auth/me. Any 401 from the
 * API clears the session; the route guard then redirects to /login.
 */
export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const [status, setStatus] = useState<AuthStatus>('restoring');
  const [user, setUser] = useState<User | null>(null);
  const [expired, setExpired] = useState(false);

  const clearSession = useCallback(
    (wasExpired: boolean) => {
      setAuthToken(null);
      writeStoredToken(null);
      setUser(null);
      setExpired(wasExpired);
      setStatus('anonymous');
      queryClient.clear();
    },
    [queryClient],
  );

  useEffect(() => {
    setUnauthorizedHandler(() => clearSession(true));
    return () => setUnauthorizedHandler(null);
  }, [clearSession]);

  useEffect(() => {
    const stored = readStoredToken();
    const exp = stored ? tokenExpiry(stored) : null;
    if (!stored || (exp !== null && exp * 1000 <= Date.now())) {
      setAuthToken(null);
      writeStoredToken(null);
      setStatus('anonymous');
      return;
    }
    setAuthToken(stored);
    let cancelled = false;
    api
      .me()
      .then((me) => {
        if (cancelled) return;
        setUser(me);
        setStatus('authenticated');
      })
      .catch(() => {
        if (!cancelled) clearSession(false);
      });
    return () => {
      cancelled = true;
    };
  }, [clearSession]);

  const login = useCallback(async (email: string, password: string) => {
    const { token } = await api.login(email, password);
    setAuthToken(token);
    const me = await api.me();
    writeStoredToken(token);
    setUser(me);
    setExpired(false);
    setStatus('authenticated');
  }, []);

  const logout = useCallback(() => clearSession(false), [clearSession]);

  const value = useMemo(
    () => ({ status, user, expired, login, logout }),
    [status, user, expired, login, logout],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>');
  return ctx;
}
