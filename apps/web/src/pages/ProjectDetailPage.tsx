import { useQuery, useQueryClient } from '@tanstack/react-query';
import type { Scan } from '@webguard/core';
import { useEffect, useRef, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { ApiError } from '../api/client';
import { api } from '../api/endpoints';
import { uploadProjectZip, type UploadHandle } from '../api/upload';
import { GradeBadge, StatusBadge } from '../components/Badges';
import { Dropzone } from '../components/Dropzone';
import { EmptyState, ErrorState, Loading } from '../components/States';
import { formatDateTime, formatDuration } from '../lib/findings';

const active = (s: Scan) => s.status === 'queued' || s.status === 'running';

export function ProjectDetailPage() {
  const { projectId = '' } = useParams();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [progress, setProgress] = useState<number | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const handle = useRef<UploadHandle | null>(null);

  useEffect(() => () => handle.current?.abort(), []);

  const project = useQuery({
    queryKey: ['project', projectId],
    queryFn: () => api.getProject(projectId),
  });
  const scans = useQuery({
    queryKey: ['scans', projectId],
    queryFn: () => api.listScans(projectId),
    enabled: project.isSuccess,
    refetchInterval: (q) => (q.state.data?.some(active) ? 3000 : false),
  });

  const upload = (file: File) => {
    setUploadError(null);
    setProgress(0);
    handle.current = uploadProjectZip(projectId, file, setProgress);
    handle.current.promise
      .then((scan) => {
        handle.current = null;
        void qc.invalidateQueries({ queryKey: ['scans', projectId] });
        void qc.invalidateQueries({ queryKey: ['projects'] });
        navigate(`/scans/${scan.id}`);
      })
      .catch((err: unknown) => {
        handle.current = null;
        setProgress(null);
        setUploadError(err instanceof ApiError ? err.message : 'Upload failed.');
      });
  };

  if (project.isPending) return <Loading label="Loading project…" />;
  if (project.isError) return <ErrorState title="Project unavailable" error={project.error} />;

  return (
    <div className="page">
      <nav aria-label="Breadcrumb" className="crumbs">
        <Link to="/projects">Projects</Link> <span aria-hidden="true">/</span>{' '}
        <span aria-current="page">{project.data.name}</span>
      </nav>
      <div className="page-head">
        <h1>{project.data.name}</h1>
      </div>

      <section className="card" aria-labelledby="upload-title">
        <h2 id="upload-title">New scan</h2>
        <Dropzone
          onFile={upload}
          disabled={progress !== null}
          progress={progress}
          error={uploadError}
        />
        {progress !== null && progress < 1 && (
          <button
            type="button"
            className="btn btn-small btn-ghost"
            onClick={() => handle.current?.abort()}
          >
            Cancel upload
          </button>
        )}
      </section>

      <section aria-labelledby="history-title">
        <h2 id="history-title">Scan history</h2>
        {scans.isPending ? (
          <Loading label="Loading scans…" />
        ) : scans.isError ? (
          <ErrorState error={scans.error} onRetry={() => scans.refetch()} />
        ) : scans.data.length === 0 ? (
          <EmptyState title="No scans yet">Drop a ZIP above to run the first scan.</EmptyState>
        ) : (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th scope="col">Started</th>
                  <th scope="col">Status</th>
                  <th scope="col">Grade</th>
                  <th scope="col" className="num">
                    Findings
                  </th>
                  <th scope="col">Duration</th>
                  <th scope="col">
                    <span className="visually-hidden">Open</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {scans.data.map((s) => {
                  const r = s.summary?.rollup;
                  return (
                    <tr key={s.id}>
                      <td>{formatDateTime(s.createdAt)}</td>
                      <td>
                        <StatusBadge status={s.status} />
                      </td>
                      <td>
                        {r ? <GradeBadge grade={r.grade} /> : <span className="muted">—</span>}
                      </td>
                      <td className="num">{r ? r.total : '—'}</td>
                      <td>{formatDuration(s.startedAt, s.finishedAt) ?? '—'}</td>
                      <td>
                        <Link to={`/scans/${s.id}`}>
                          {s.status === 'completed' ? 'View results' : 'View'}
                        </Link>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
