import type { Language } from '@webguard/core';

const NAMES: Partial<Record<Language, string>> = {
  javascript: 'JavaScript',
  typescript: 'TypeScript',
  csharp: 'C#',
  php: 'PHP',
  html: 'HTML',
  css: 'CSS',
  json: 'JSON',
  yaml: 'YAML',
  toml: 'TOML',
  xml: 'XML',
  sql: 'SQL',
  dockerfile: 'Dockerfile',
};

export function languageName(language: Language | null | undefined): string {
  if (!language) return 'Other';
  return NAMES[language] ?? language.charAt(0).toUpperCase() + language.slice(1);
}

/** 1234 → "1,234"; null → "—". */
export function formatCount(n: number | null | undefined): string {
  return n === null || n === undefined ? '—' : n.toLocaleString();
}

/** 2 500 → "2.5 s"; 125 000 → "2 min 5 s". */
export function formatMs(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return '—';
  if (ms < 1000) return `${ms} ms`;
  const s = ms / 1000;
  if (s < 60) return `${Math.round(s * 10) / 10} s`;
  return `${Math.floor(s / 60)} min ${Math.round(s % 60)} s`;
}

export const percent = (part: number, whole: number) =>
  whole > 0 ? `${Math.round((part / whole) * 1000) / 10}%` : '0%';
