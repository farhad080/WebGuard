import type { Scan } from '@webguard/core';
import { ApiError, apiUrl, authHeaders, handleUnauthorized } from './client';

export interface UploadHandle {
  promise: Promise<Scan>;
  abort: () => void;
}

/**
 * Uploads a ZIP with XMLHttpRequest (fetch has no upload-progress events).
 * `onProgress` receives 0–1 as bytes leave the browser.
 */
export function uploadProjectZip(
  projectId: string,
  file: File,
  onProgress: (fraction: number) => void,
): UploadHandle {
  const xhr = new XMLHttpRequest();
  const promise = new Promise<Scan>((resolve, reject) => {
    xhr.open('POST', apiUrl(`/api/projects/${encodeURIComponent(projectId)}/scans`));
    for (const [k, v] of Object.entries(authHeaders())) xhr.setRequestHeader(k, v);
    xhr.responseType = 'json';
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable && e.total > 0) onProgress(e.loaded / e.total);
    };
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        onProgress(1);
        resolve(xhr.response as Scan);
        return;
      }
      handleUnauthorized(xhr.status);
      const body = xhr.response as { error?: string } | null;
      reject(new ApiError(xhr.status, body?.error ?? `Upload failed (${xhr.status})`));
    };
    xhr.onerror = () => reject(new ApiError(0, 'Network error during upload.'));
    xhr.onabort = () => reject(new ApiError(0, 'Upload cancelled.'));
    const form = new FormData();
    form.append('file', file, file.name);
    xhr.send(form);
  });
  return { promise, abort: () => xhr.abort() };
}
