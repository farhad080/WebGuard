import type { InformationalNote } from '@webguard/core';

/**
 * Documented challenges / weakness classes that are not code defects detectable from source.
 * Attached to every scan summary so reports can list them as "review manually" instead of
 * silently omitting them.
 */
export const INFORMATIONAL_NOTES: readonly InformationalNote[] = [
  {
    id: 'weak-password-policy',
    title: 'Weak password policy',
    references: ['Juice Shop #15'],
    note:
      'Password strength rules are policy, often enforced only in the UI or by configuration. ' +
      'Review the registration and password-change endpoints (minimum length, breached-password ' +
      'checks, rate limiting) and try weak passwords against a running instance.',
  },
  {
    id: 'information-disclosure',
    title: 'Information disclosure in published content',
    references: ['Juice Shop #17'],
    note:
      'Secrets hidden in images, documents, metadata, or blog/marketing content are not ' +
      'visible to code analysis. Review published assets and run a dynamic/OSINT check. ' +
      'Obvious cases (backups, keys in served dirs) are reported by A7.',
  },
  {
    id: 'discovery',
    title: 'Discovery / reconnaissance challenges',
    references: ['Juice Shop #33', 'Juice Shop #34'],
    note:
      'Finding hidden pages, score boards, or easter eggs is exploration, not a code defect. ' +
      'Review client-side route definitions and served assets manually or with a crawler.',
  },
];
