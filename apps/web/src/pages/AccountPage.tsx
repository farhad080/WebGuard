import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../auth/AuthContext';
import { applyThemePreference, readThemePreference, type ThemePreference } from '../lib/theme';

export function AccountPage() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [theme, setTheme] = useState<ThemePreference>(readThemePreference);

  const changeTheme = (pref: ThemePreference) => {
    setTheme(pref);
    applyThemePreference(pref);
  };

  return (
    <div className="page page-narrow">
      <h1>Account</h1>
      <section className="card" aria-labelledby="profile-title">
        <h2 id="profile-title">Profile</h2>
        <dl>
          <dt>Email</dt>
          <dd data-testid="account-email">{user?.email}</dd>
        </dl>
        <p className="small">
          To change your password, use <Link to="/forgot-password">password reset</Link>.
        </p>
      </section>

      <section className="card" aria-labelledby="appearance-title">
        <h2 id="appearance-title">Appearance</h2>
        <fieldset className="radio-row">
          <legend>Theme</legend>
          {(['system', 'light', 'dark'] as const).map((t) => (
            <label key={t} className="chip">
              <input
                type="radio"
                name="theme"
                value={t}
                checked={theme === t}
                onChange={() => changeTheme(t)}
              />
              {t === 'system' ? 'Match system' : t === 'light' ? 'Light' : 'Dark'}
            </label>
          ))}
        </fieldset>
      </section>

      <section className="card" aria-labelledby="session-title">
        <h2 id="session-title">Session</h2>
        <p className="muted small">Signing out removes the session from this browser.</p>
        <button
          type="button"
          className="btn btn-danger"
          onClick={() => {
            logout();
            navigate('/login', { replace: true });
          }}
        >
          Sign out
        </button>
      </section>
    </div>
  );
}
