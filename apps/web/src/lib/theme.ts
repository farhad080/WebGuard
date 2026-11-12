import { useSyncExternalStore } from 'react';

export type ThemePreference = 'system' | 'light' | 'dark';
export const THEME_STORAGE_KEY = 'webguard.theme';

export function readThemePreference(): ThemePreference {
  try {
    const v = window.localStorage.getItem(THEME_STORAGE_KEY);
    return v === 'light' || v === 'dark' ? v : 'system';
  } catch {
    return 'system';
  }
}

/** Applies the preference as `data-theme` on <html> (absent = follow the OS). */
export function applyThemePreference(pref: ThemePreference): void {
  const root = document.documentElement;
  if (pref === 'system') root.removeAttribute('data-theme');
  else root.setAttribute('data-theme', pref);
  try {
    if (pref === 'system') window.localStorage.removeItem(THEME_STORAGE_KEY);
    else window.localStorage.setItem(THEME_STORAGE_KEY, pref);
  } catch {
    // Not persisted; still applied for this visit.
  }
}

function resolvedMode(): 'light' | 'dark' {
  const attr = document.documentElement.getAttribute('data-theme');
  if (attr === 'light' || attr === 'dark') return attr;
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function subscribe(cb: () => void): () => void {
  const mq = window.matchMedia?.('(prefers-color-scheme: dark)');
  mq?.addEventListener?.('change', cb);
  const obs = new MutationObserver(cb);
  obs.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
  return () => {
    mq?.removeEventListener?.('change', cb);
    obs.disconnect();
  };
}

export function useColorMode(): 'light' | 'dark' {
  return useSyncExternalStore(subscribe, resolvedMode, () => 'light');
}

/**
 * Chart colors, selected per mode (not auto-flipped). Severity is ORDINAL (critical → info),
 * so it takes one red ramp with monotone lightness — validated with the dataviz validator
 * (`--ordinal`) against each surface. OWASP categories are one nominal series → slot-1 blue.
 */
export const CHART_THEME = {
  light: {
    surface: '#fcfcfb',
    textPrimary: '#0b0b0b',
    textSecondary: '#52514e',
    muted: '#898781',
    grid: '#e1e0d9',
    axis: '#c3c2b7',
    series1: '#2a78d6',
    severity: {
      critical: '#7a1414',
      high: '#a82424',
      medium: '#d03b3b',
      low: '#e2706a',
      info: '#ec9a94',
    },
  },
  dark: {
    surface: '#1a1a19',
    textPrimary: '#f0efec',
    textSecondary: '#c3c2b7',
    muted: '#898781',
    grid: '#2c2c2a',
    axis: '#383835',
    series1: '#3987e5',
    severity: {
      critical: '#ffb3ad',
      high: '#f3837b',
      medium: '#e25550',
      low: '#c23a3a',
      info: '#9a2c2c',
    },
  },
} as const;

export function useChartTheme() {
  return CHART_THEME[useColorMode()];
}
