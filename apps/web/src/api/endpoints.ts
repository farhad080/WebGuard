import type {
  Finding,
  OwaspCategory,
  Project,
  ProjectWithLastScan,
  Scan,
  ScanComparison,
  ScanFile,
  ScanStatsResponse,
  Severity,
} from '@webguard/core';
import { ApiError, apiFetch, apiJson } from './client';

export interface User {
  id: string;
  email: string;
}

const enc = encodeURIComponent;

export interface ServerLimits {
  maxUploadMb: number;
  maxUploadBytes: number;
}

export const api = {
  // public server limits (MAX_UPLOAD_MB), so the uploader checks the real cap
  limits: () => apiJson<ServerLimits>('/api/limits'),

  // auth
  login: (email: string, password: string) =>
    apiJson<{ token: string }>('/api/auth/login', { method: 'POST', json: { email, password } }),
  register: (email: string, password: string) =>
    apiJson<User>('/api/auth/register', { method: 'POST', json: { email, password } }),
  me: () => apiJson<User>('/api/auth/me'),
  forgotPassword: (email: string) =>
    apiJson<{ message: string }>('/api/auth/forgot-password', { method: 'POST', json: { email } }),
  resetPassword: (token: string, password: string) =>
    apiJson<void>('/api/auth/reset-password', { method: 'POST', json: { token, password } }),

  // projects
  listProjects: () => apiJson<ProjectWithLastScan[]>('/api/projects'),
  getProject: (id: string) => apiJson<Project>(`/api/projects/${enc(id)}`),
  createProject: (name: string) =>
    apiJson<Project>('/api/projects', { method: 'POST', json: { name } }),
  renameProject: (id: string, name: string) =>
    apiJson<Project>(`/api/projects/${enc(id)}`, { method: 'PATCH', json: { name } }),
  deleteProject: (id: string) => apiJson<void>(`/api/projects/${enc(id)}`, { method: 'DELETE' }),

  // scans & findings
  listScans: (projectId: string) => apiJson<Scan[]>(`/api/projects/${enc(projectId)}/scans`),
  getScan: (id: string) => apiJson<Scan>(`/api/scans/${enc(id)}`),
  listFindings: (
    scanId: string,
    filter: { severity?: Severity[]; owaspCategory?: OwaspCategory; minConfidence?: number } = {},
  ) => {
    const q = new URLSearchParams();
    if (filter.severity?.length) q.set('severity', filter.severity.join(','));
    if (filter.owaspCategory) q.set('owaspCategory', filter.owaspCategory);
    if (filter.minConfidence !== undefined) q.set('minConfidence', String(filter.minConfidence));
    const qs = q.toString();
    return apiJson<Finding[]>(`/api/scans/${enc(scanId)}/findings${qs ? `?${qs}` : ''}`);
  },
  getFinding: (id: string) => apiJson<Finding>(`/api/findings/${enc(id)}`),
  compareScans: (scanId: string, againstId: string) =>
    apiJson<ScanComparison>(`/api/scans/${enc(scanId)}/compare?against=${enc(againstId)}`),
  /** Project Overview statistics stored with the scan (partial for a failed scan). */
  getStats: (scanId: string) => apiJson<ScanStatsResponse>(`/api/scans/${enc(scanId)}/stats`),
  /** One file of the scan's extracted copy (secret-redacted, size-capped). */
  getFile: (scanId: string, path: string) =>
    apiJson<ScanFile>(`/api/scans/${enc(scanId)}/file?path=${enc(path)}`),

  // reports
  reportHtml: (scanId: string) => apiJson<string>(`/api/scans/${enc(scanId)}/report.html`),
  /** Resolves to the file blob; throws ApiError(202) while the PDF is still rendering. */
  reportBlob: async (scanId: string, kind: 'json' | 'pdf'): Promise<Blob> => {
    const res = await apiFetch(`/api/scans/${enc(scanId)}/report.${kind}`);
    if (res.status === 202) {
      const retry = Number(res.headers.get('Retry-After') ?? 10);
      throw new ApiError(202, `The PDF is still being generated. Try again in ${retry}s.`);
    }
    return res.blob();
  },
};
