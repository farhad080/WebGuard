import { rm } from 'node:fs/promises';
import type { ProjectProfile } from '@webguard/core';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { materializeMiniExpress } from '../../test/fixture-project.js';
import { detectLanguage } from './languages.js';
import { ProfilerService } from './profiler.js';

let root: string;
let profile: ProjectProfile;

beforeAll(async () => {
  root = await materializeMiniExpress();
  // Small cap so the generated vendor.min.js (6 KB) counts as oversized.
  profile = await new ProfilerService({ maxFileBytes: 4096 }).profile(root);
});

afterAll(async () => {
  await rm(root, { recursive: true, force: true });
});

describe('ProfilerService on the mini-express fixture', () => {
  it('detects languages with per-language file counts', () => {
    const counts = Object.fromEntries(profile.languages.map((l) => [l.language, l.files]));
    expect(counts).toEqual({
      javascript: 4, // users.js, widget.js, broken.js, scripts/start (shebang)
      typescript: 1,
      json: 2,
      yaml: 2,
      html: 1,
      dockerfile: 1,
      markdown: 1,
    });
    expect(profile.languages[0]?.language).toBe('javascript'); // sorted by count
  });

  it('detects Node.js and Express from package.json', () => {
    expect(profile.frameworks).toEqual(
      expect.arrayContaining([
        { name: 'Node.js', kind: 'runtime', evidence: 'package.json' },
        { name: 'Express', kind: 'framework', evidence: 'package.json' },
      ]),
    );
    expect(profile.frameworks.map((f) => f.name)).not.toContain('React');
  });

  it('locates manifests and lockfiles', () => {
    expect(profile.manifests).toEqual([
      { path: 'package-lock.json', type: 'package-lock.json', kind: 'lockfile' },
      { path: 'package.json', type: 'package.json', kind: 'manifest' },
    ]);
  });

  it('locates config, IaC, secrets, and served paths', () => {
    expect(profile.sensitivePaths).toEqual(
      expect.arrayContaining([
        { path: '.env', category: 'env' },
        { path: 'Dockerfile', category: 'dockerfile' },
        { path: 'docker-compose.yml', category: 'compose' },
        { path: 'infra/deploy.yml', category: 'infra-config' },
        { path: 'public/index.html', category: 'static-served' },
        { path: 'public/logo.png', category: 'static-served' },
      ]),
    );
  });

  it('ignores node_modules, dist, .git, binaries, and oversized files', () => {
    const paths = profile.sourceFiles.map((f) => f.path);
    expect(paths.some((p) => p.startsWith('node_modules/'))).toBe(false);
    expect(paths.some((p) => p.startsWith('dist/') || p.startsWith('.git/'))).toBe(false);
    expect(paths).not.toContain('public/logo.png');
    expect(paths).not.toContain('src/vendor.min.js');
    expect(profile.ignored.byReason).toEqual({
      'ignored-dir': 4, // node_modules (2) + dist (1) + .git (1)
      binary: 1,
      'too-large': 1,
      unrecognized: 2, // .env, LICENSE
    });
    expect(profile.manifests.map((m) => m.path)).not.toContain('node_modules/express/package.json');
  });

  it('lists the source files to analyze', () => {
    expect(
      profile.sourceFiles.filter((f) => ['javascript', 'typescript'].includes(f.language)),
    ).toEqual([
      { path: 'scripts/start', language: 'javascript', bytes: expect.any(Number) },
      { path: 'src/client/widget.js', language: 'javascript', bytes: expect.any(Number) },
      { path: 'src/legacy/broken.js', language: 'javascript', bytes: expect.any(Number) },
      { path: 'src/routes/users.js', language: 'javascript', bytes: expect.any(Number) },
      { path: 'src/server.ts', language: 'typescript', bytes: expect.any(Number) },
    ]);
  });
});

describe('detectLanguage', () => {
  it.each([
    ['app.tsx', undefined, 'typescript'],
    ['index.mjs', undefined, 'javascript'],
    ['Dockerfile.prod', undefined, 'dockerfile'],
    ['main.tf', undefined, 'terraform'],
    ['run', '#!/usr/bin/env python3\nprint(1)', 'python'],
    ['deploy', '#!/bin/bash\necho hi', 'shell'],
    ['index', '<?php echo 1;', 'php'],
    ['LICENSE', 'MIT License', null],
  ])('%s → %s', (name, head, expected) => {
    expect(detectLanguage(name, head)).toBe(expected);
  });
});
