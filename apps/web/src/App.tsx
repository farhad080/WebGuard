import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { lazy, Suspense, useState, type ReactNode } from 'react';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { ApiError } from './api/client';
import { AuthProvider } from './auth/AuthContext';
import { RedirectIfAuthed, RequireAuth } from './auth/RequireAuth';
import { AppLayout } from './components/Layout';
import { Loading } from './components/States';
import { AccountPage } from './pages/AccountPage';
import { ForgotPasswordPage, LoginPage, RegisterPage, ResetPasswordPage } from './pages/AuthPages';
import { NotFoundPage } from './pages/NotFoundPage';
import { ProjectDetailPage } from './pages/ProjectDetailPage';
import { ProjectsPage } from './pages/ProjectsPage';

// Charts and Monaco are heavy: load the scan, finding, and report pages on demand.
const ScanPage = lazy(() => import('./pages/ScanPage').then((m) => ({ default: m.ScanPage })));
const FindingPage = lazy(() =>
  import('./pages/FindingPage').then((m) => ({ default: m.FindingPage })),
);
const HistoryPage = lazy(() =>
  import('./pages/HistoryPage').then((m) => ({ default: m.HistoryPage })),
);
const ReportViewerPage = lazy(() =>
  import('./pages/ReportViewerPage').then((m) => ({ default: m.ReportViewerPage })),
);

const page = (node: ReactNode) => <Suspense fallback={<Loading />}>{node}</Suspense>;

export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 10_000,
        refetchOnWindowFocus: false,
        // Client errors (401/403/404/409) won't succeed on retry; network blips might.
        retry: (count, err) =>
          count < 2 && !(err instanceof ApiError && err.status >= 400 && err.status < 500),
      },
    },
  });
}

export function AppRoutes() {
  return (
    <Routes>
      <Route
        path="/login"
        element={
          <RedirectIfAuthed>
            <LoginPage />
          </RedirectIfAuthed>
        }
      />
      <Route
        path="/register"
        element={
          <RedirectIfAuthed>
            <RegisterPage />
          </RedirectIfAuthed>
        }
      />
      <Route path="/forgot-password" element={<ForgotPasswordPage />} />
      <Route path="/reset-password" element={<ResetPasswordPage />} />
      <Route
        element={
          <RequireAuth>
            <AppLayout />
          </RequireAuth>
        }
      >
        <Route index element={<Navigate to="/projects" replace />} />
        <Route path="/projects" element={<ProjectsPage />} />
        <Route path="/projects/:projectId" element={<ProjectDetailPage />} />
        <Route path="/projects/:projectId/history" element={page(<HistoryPage />)} />
        <Route path="/scans/:scanId" element={page(<ScanPage />)} />
        <Route path="/scans/:scanId/report" element={page(<ReportViewerPage />)} />
        <Route path="/findings/:findingId" element={page(<FindingPage />)} />
        <Route path="/account" element={<AccountPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}

/** Providers shared by the app and the tests (the router is supplied by the caller). */
export function Providers({ client, children }: { client: QueryClient; children: ReactNode }) {
  return (
    <QueryClientProvider client={client}>
      <AuthProvider>{children}</AuthProvider>
    </QueryClientProvider>
  );
}

export function App() {
  const [client] = useState(createQueryClient);
  return (
    <Providers client={client}>
      <BrowserRouter>
        <AppRoutes />
      </BrowserRouter>
    </Providers>
  );
}
