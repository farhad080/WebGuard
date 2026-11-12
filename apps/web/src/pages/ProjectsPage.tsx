import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { ProjectWithLastScan } from '@webguard/core';
import { useState, type FormEvent } from 'react';
import { Link } from 'react-router-dom';
import { ApiError } from '../api/client';
import { api } from '../api/endpoints';
import { GradeBadge, SeverityBadge, StatusBadge } from '../components/Badges';
import { EmptyState, ErrorState, Loading } from '../components/States';
import { formatDateTime } from '../lib/findings';

const isActive = (p: ProjectWithLastScan) =>
  p.lastScan?.status === 'queued' || p.lastScan?.status === 'running';

function LastScanSummary({ project }: { project: ProjectWithLastScan }) {
  const scan = project.lastScan;
  if (!scan) return <p className="muted small">No scans yet — upload a ZIP to start.</p>;
  const r = scan.rollup;
  return (
    <div className="last-scan">
      <div className="last-scan-head">
        {r ? <GradeBadge grade={r.grade} /> : null}
        <StatusBadge status={scan.status} />
        <span className="muted small">{formatDateTime(scan.finishedAt ?? scan.createdAt)}</span>
      </div>
      {r && (
        <div className="sev-counts" aria-label="Last scan findings by severity">
          {r.total === 0 ? (
            <span className="muted small">No findings</span>
          ) : (
            (['critical', 'high', 'medium'] as const)
              .filter((s) => r.bySeverity[s] > 0)
              .map((s) => (
                <span key={s} className="sev-count">
                  <SeverityBadge severity={s} /> {r.bySeverity[s]}
                </span>
              ))
          )}
          {r.total > 0 && <span className="muted small">{r.total} total</span>}
        </div>
      )}
    </div>
  );
}

function ProjectCard({ project }: { project: ProjectWithLastScan }) {
  const qc = useQueryClient();
  const [editing, setEditing] = useState(false);
  const [name, setName] = useState(project.name);
  const [confirmDelete, setConfirmDelete] = useState(false);

  const rename = useMutation({
    mutationFn: (next: string) => api.renameProject(project.id, next),
    onSuccess: () => {
      setEditing(false);
      return qc.invalidateQueries({ queryKey: ['projects'] });
    },
  });
  const remove = useMutation({
    mutationFn: () => api.deleteProject(project.id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['projects'] }),
  });

  return (
    <li className="card project-card">
      {editing ? (
        <form
          className="inline-form"
          onSubmit={(e) => {
            e.preventDefault();
            if (name.trim()) rename.mutate(name.trim());
          }}
        >
          <label className="visually-hidden" htmlFor={`rename-${project.id}`}>
            Project name
          </label>
          <input
            id={`rename-${project.id}`}
            value={name}
            maxLength={200}
            autoFocus
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => e.key === 'Escape' && setEditing(false)}
          />
          <button type="submit" className="btn btn-small btn-primary" disabled={rename.isPending}>
            Save
          </button>
          <button
            type="button"
            className="btn btn-small btn-ghost"
            onClick={() => setEditing(false)}
          >
            Cancel
          </button>
        </form>
      ) : (
        <h2 className="project-name">
          <Link to={`/projects/${project.id}`}>{project.name}</Link>
        </h2>
      )}
      {rename.isError && (
        <p className="field-error" role="alert">
          {(rename.error as ApiError).message}
        </p>
      )}
      <LastScanSummary project={project} />
      <div className="card-actions">
        {confirmDelete ? (
          <>
            <span className="small">Delete “{project.name}” and all its scans?</span>
            <button
              type="button"
              className="btn btn-small btn-danger"
              disabled={remove.isPending}
              onClick={() => remove.mutate()}
            >
              {remove.isPending ? 'Deleting…' : 'Delete'}
            </button>
            <button
              type="button"
              className="btn btn-small btn-ghost"
              onClick={() => setConfirmDelete(false)}
            >
              Keep
            </button>
          </>
        ) : (
          <>
            <button
              type="button"
              className="btn btn-small btn-ghost"
              onClick={() => {
                setName(project.name);
                setEditing(true);
              }}
              aria-label={`Rename ${project.name}`}
            >
              Rename
            </button>
            <button
              type="button"
              className="btn btn-small btn-ghost danger-text"
              onClick={() => setConfirmDelete(true)}
              aria-label={`Delete ${project.name}`}
            >
              Delete
            </button>
          </>
        )}
      </div>
      {remove.isError && (
        <p className="field-error" role="alert">
          {(remove.error as ApiError).message}
        </p>
      )}
    </li>
  );
}

export function ProjectsPage() {
  const qc = useQueryClient();
  const [name, setName] = useState('');
  const projects = useQuery({
    queryKey: ['projects'],
    queryFn: api.listProjects,
    // Keep cards fresh while any project's latest scan is still in flight.
    refetchInterval: (q) => (q.state.data?.some(isActive) ? 3000 : false),
  });
  const create = useMutation({
    mutationFn: (n: string) => api.createProject(n),
    onSuccess: () => {
      setName('');
      return qc.invalidateQueries({ queryKey: ['projects'] });
    },
  });

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (name.trim()) create.mutate(name.trim());
  };

  return (
    <div className="page">
      <div className="page-head">
        <h1>Projects</h1>
      </div>
      <form className="create-form card" onSubmit={submit}>
        <label className="field grow">
          <span>New project</span>
          <input
            placeholder="e.g. Shop frontend"
            value={name}
            maxLength={200}
            onChange={(e) => setName(e.target.value)}
          />
        </label>
        <button
          type="submit"
          className="btn btn-primary"
          disabled={!name.trim() || create.isPending}
        >
          {create.isPending ? 'Creating…' : 'Create project'}
        </button>
        {create.isError && (
          <p className="field-error" role="alert">
            {(create.error as ApiError).message}
          </p>
        )}
      </form>

      {projects.isPending ? (
        <Loading label="Loading projects…" />
      ) : projects.isError ? (
        <ErrorState error={projects.error} onRetry={() => projects.refetch()} />
      ) : projects.data.length === 0 ? (
        <EmptyState title="No projects yet">
          Create a project above, then upload a ZIP of its source code to scan it.
        </EmptyState>
      ) : (
        <ul className="project-grid">
          {projects.data.map((p) => (
            <ProjectCard key={p.id} project={p} />
          ))}
        </ul>
      )}
    </div>
  );
}
