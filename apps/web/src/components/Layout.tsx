import { Link, NavLink, Outlet } from 'react-router-dom';
import { useAuth } from '../auth/AuthContext';

export function AppLayout() {
  const { user } = useAuth();
  return (
    <div className="app">
      <a href="#main" className="skip-link">
        Skip to content
      </a>
      <header className="topbar">
        <Link to="/projects" className="brand">
          <span className="brand-mark" aria-hidden="true">
            ⛨
          </span>
          WebGuard
        </Link>
        <nav aria-label="Main">
          <NavLink to="/projects">Projects</NavLink>
          <NavLink to="/account" title={user?.email}>
            Account
          </NavLink>
        </nav>
      </header>
      <main id="main" className="main" tabIndex={-1}>
        <Outlet />
      </main>
    </div>
  );
}

export function AuthLayout({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <main className="auth-page">
      <div className="auth-card card">
        <div className="brand auth-brand">
          <span className="brand-mark" aria-hidden="true">
            ⛨
          </span>
          WebGuard
        </div>
        <h1>{title}</h1>
        {children}
      </div>
    </main>
  );
}
