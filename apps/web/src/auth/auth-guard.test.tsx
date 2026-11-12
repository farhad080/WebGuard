import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { mockApi, renderApp, user } from '../test/utils';
import { TOKEN_STORAGE_KEY } from './AuthContext';

describe('auth guard', () => {
  it('redirects an anonymous visitor from a private route to /login', async () => {
    const { calls } = mockApi({});
    renderApp('/projects', { signedIn: false });
    expect(await screen.findByRole('heading', { name: 'Sign in' })).toBeInTheDocument();
    expect(calls.some((c) => c.path === '/api/projects')).toBe(false);
  });

  it('restores a stored session and sends the Bearer token on every request', async () => {
    const { calls } = mockApi({
      'GET /api/auth/me': () => ({ body: user }),
      'GET /api/projects': () => ({ body: [] }),
    });
    renderApp('/projects');
    expect(await screen.findByRole('heading', { name: 'Projects' })).toBeInTheDocument();
    expect(await screen.findByText('No projects yet')).toBeInTheDocument();
    const token = window.localStorage.getItem(TOKEN_STORAGE_KEY);
    expect(calls.length).toBeGreaterThanOrEqual(2);
    for (const c of calls) expect(c.headers.get('Authorization')).toBe(`Bearer ${token}`);
  });

  it('drops a stored token the API rejects and shows the login page', async () => {
    mockApi({ 'GET /api/auth/me': () => ({ status: 401, body: { error: 'Unauthorized' } }) });
    renderApp('/projects');
    expect(await screen.findByRole('heading', { name: 'Sign in' })).toBeInTheDocument();
    expect(window.localStorage.getItem(TOKEN_STORAGE_KEY)).toBeNull();
  });

  it('ends the session on a 401 from any later request', async () => {
    mockApi({
      'GET /api/auth/me': () => ({ body: user }),
      'GET /api/projects': () => ({ status: 401, body: { error: 'Unauthorized' } }),
    });
    renderApp('/projects');
    expect(await screen.findByRole('heading', { name: 'Sign in' })).toBeInTheDocument();
    expect(screen.getByText(/session expired/i)).toBeInTheDocument();
    expect(window.localStorage.getItem(TOKEN_STORAGE_KEY)).toBeNull();
  });

  it('logs in, stores the token, and returns to the page that was requested', async () => {
    const { calls } = mockApi({
      'POST /api/auth/login': (req) =>
        (req.body as { password: string }).password === 'correct-horse'
          ? { body: { token: 'aaa.bbb.ccc' } }
          : { status: 401, body: { error: 'Invalid email or password' } },
      'GET /api/auth/me': () => ({ body: user }),
      'GET /api/projects': () => ({ body: [] }),
    });
    renderApp('/projects', { signedIn: false });
    const ue = userEvent.setup();
    await ue.type(await screen.findByLabelText('Email'), 'alice@example.com');
    await ue.type(screen.getByLabelText('Password'), 'wrong');
    await ue.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Invalid email or password');

    await ue.clear(screen.getByLabelText('Password'));
    await ue.type(screen.getByLabelText('Password'), 'correct-horse');
    await ue.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(await screen.findByRole('heading', { name: 'Projects' })).toBeInTheDocument();
    expect(window.localStorage.getItem(TOKEN_STORAGE_KEY)).toBe('aaa.bbb.ccc');
    await waitFor(() =>
      expect(calls.find((c) => c.path === '/api/projects')?.headers.get('Authorization')).toBe(
        'Bearer aaa.bbb.ccc',
      ),
    );
  });

  it('signs out from account settings', async () => {
    mockApi({ 'GET /api/auth/me': () => ({ body: user }) });
    renderApp('/account');
    expect(await screen.findByTestId('account-email')).toHaveTextContent(user.email);
    await userEvent.click(screen.getByRole('button', { name: 'Sign out' }));
    expect(await screen.findByRole('heading', { name: 'Sign in' })).toBeInTheDocument();
    expect(window.localStorage.getItem(TOKEN_STORAGE_KEY)).toBeNull();
  });
});
