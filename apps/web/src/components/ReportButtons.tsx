import { useState } from 'react';
import { Link } from 'react-router-dom';
import { ApiError } from '../api/client';
import { api } from '../api/endpoints';

function saveBlob(blob: Blob, fileName: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = fileName;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

/**
 * Report exports. Downloads go through fetch (so the Bearer token is sent) and are saved
 * from a Blob. The HTML report opens in an in-app sandboxed viewer, never as a same-origin page.
 */
export function ReportButtons({ scanId }: { scanId: string }) {
  const [busy, setBusy] = useState<'json' | 'pdf' | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const download = async (kind: 'json' | 'pdf') => {
    setBusy(kind);
    setMessage(kind === 'pdf' ? 'Preparing PDF…' : null);
    try {
      const blob = await api.reportBlob(scanId, kind);
      saveBlob(blob, `webguard-report-${scanId}.${kind}`);
      setMessage(null);
    } catch (err) {
      setMessage(err instanceof ApiError ? err.message : 'Download failed.');
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="report-buttons">
      <Link className="btn btn-secondary" to={`/scans/${scanId}/report`}>
        Open HTML report
      </Link>
      <button
        type="button"
        className="btn btn-secondary"
        disabled={busy !== null}
        onClick={() => download('pdf')}
      >
        {busy === 'pdf' ? 'Generating PDF…' : 'Download PDF'}
      </button>
      <button
        type="button"
        className="btn btn-secondary"
        disabled={busy !== null}
        onClick={() => download('json')}
      >
        {busy === 'json' ? 'Downloading…' : 'Download JSON'}
      </button>
      {message && (
        <span className="muted small" role="status">
          {message}
        </span>
      )}
    </div>
  );
}
