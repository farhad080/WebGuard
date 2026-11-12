import type { ReactNode } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { Loading } from '../components/States';
import { useAuth } from './AuthContext';

/** Guards private routes: waits for session restore, then redirects anonymous users to /login. */
export function RequireAuth({ children }: { children: ReactNode }) {
  const { status } = useAuth();
  const location = useLocation();
  if (status === 'restoring') return <Loading label="Restoring your session…" />;
  if (status === 'anonymous') {
    return <Navigate to="/login" replace state={{ from: location.pathname + location.search }} />;
  }
  return <>{children}</>;
}

/** For /login and /register: an authenticated user goes straight to their projects. */
export function RedirectIfAuthed({ children }: { children: ReactNode }) {
  const { status } = useAuth();
  if (status === 'restoring') return <Loading label="Restoring your session…" />;
  if (status === 'authenticated') return <Navigate to="/projects" replace />;
  return <>{children}</>;
}
