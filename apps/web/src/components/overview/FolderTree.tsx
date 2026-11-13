import type { StatsTreeNode } from '@webguard/core';
import { useState } from 'react';
import { SEVERITY_LABEL } from '../../lib/findings';

/**
 * The project's folder tree (as stored with the scan, already capped). Directories expand and
 * collapse; each row shows its file and finding counts, and is marked with the worst severity
 * in its subtree (swatch + text, never color alone). Files open the file viewer.
 */
export function FolderTree({
  root,
  onOpenFile,
}: {
  root: StatsTreeNode;
  onOpenFile: (path: string) => void;
}) {
  // Top-level folders start open; deeper ones on demand.
  const [open, setOpen] = useState<Set<string>>(() => new Set(['']));
  const toggle = (path: string) =>
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(path)) next.delete(path);
      else next.add(path);
      return next;
    });

  const allDirs = (n: StatsTreeNode): string[] =>
    n.type === 'dir' ? [n.path, ...(n.children ?? []).flatMap(allDirs)] : [];

  return (
    <div className="folder-tree">
      <div className="folder-tree-actions">
        <button
          type="button"
          className="btn btn-small btn-ghost"
          onClick={() => setOpen(new Set(allDirs(root)))}
        >
          Expand all
        </button>
        <button
          type="button"
          className="btn btn-small btn-ghost"
          onClick={() => setOpen(new Set(['']))}
        >
          Collapse all
        </button>
      </div>
      <ul className="tree-list" aria-label="Project files">
        {(root.children ?? []).map((child) => (
          <TreeRow
            key={child.path}
            node={child}
            depth={0}
            open={open}
            onToggle={toggle}
            onOpenFile={onOpenFile}
          />
        ))}
        <Omitted node={root} depth={0} />
      </ul>
    </div>
  );
}

function SeverityMark({ node }: { node: StatsTreeNode }) {
  if (!node.worstSeverity) return <span className="tree-sev tree-sev-none" aria-hidden="true" />;
  return (
    <span
      className={`tree-sev swatch sev-${node.worstSeverity}`}
      title={`Worst: ${SEVERITY_LABEL[node.worstSeverity]}`}
      aria-hidden="true"
    />
  );
}

function Counts({ node }: { node: StatsTreeNode }) {
  return (
    <span className="tree-counts small">
      {node.type === 'dir' && (
        <span className="muted">
          {node.files.toLocaleString()} {node.files === 1 ? 'file' : 'files'}
        </span>
      )}
      {node.findings > 0 ? (
        <span className="tree-findings">
          {node.findings} {node.findings === 1 ? 'finding' : 'findings'}
          <span className="visually-hidden">
            , worst {node.worstSeverity ? SEVERITY_LABEL[node.worstSeverity] : ''}
          </span>
        </span>
      ) : null}
    </span>
  );
}

function Omitted({ node, depth }: { node: StatsTreeNode; depth: number }) {
  if (!node.omitted) return null;
  const parts = [
    node.omitted.dirs
      ? `${node.omitted.dirs} ${node.omitted.dirs === 1 ? 'folder' : 'folders'}`
      : '',
    node.omitted.files
      ? `${node.omitted.files} ${node.omitted.files === 1 ? 'file' : 'files'}`
      : '',
  ].filter(Boolean);
  return (
    <li className="tree-omitted muted small" style={{ paddingLeft: depth * 16 + 28 }}>
      +{parts.join(' and ')} not listed (tree is capped; counts above include them)
    </li>
  );
}

function TreeRow({
  node,
  depth,
  open,
  onToggle,
  onOpenFile,
}: {
  node: StatsTreeNode;
  depth: number;
  open: Set<string>;
  onToggle: (path: string) => void;
  onOpenFile: (path: string) => void;
}) {
  const indent = { paddingLeft: depth * 16 + 4 };
  if (node.type === 'file') {
    return (
      <li>
        <button
          type="button"
          className="tree-row tree-file"
          style={indent}
          onClick={() => onOpenFile(node.path)}
          aria-label={`Open ${node.path}${node.findings ? `, ${node.findings} ${node.findings === 1 ? 'finding' : 'findings'}` : ''}`}
          data-path={node.path}
        >
          <span className="tree-caret" aria-hidden="true" />
          <SeverityMark node={node} />
          <span className="tree-name mono">{node.name}</span>
          <Counts node={node} />
        </button>
      </li>
    );
  }
  const expanded = open.has(node.path);
  return (
    <li>
      <button
        type="button"
        className="tree-row tree-dir"
        style={indent}
        aria-expanded={expanded}
        onClick={() => onToggle(node.path)}
        data-path={node.path}
      >
        <span className="tree-caret" aria-hidden="true">
          {expanded ? '▾' : '▸'}
        </span>
        <SeverityMark node={node} />
        <span className="tree-name mono">{node.name}/</span>
        <Counts node={node} />
      </button>
      {expanded && (
        <ul className="tree-list">
          {(node.children ?? []).map((child) => (
            <TreeRow
              key={child.path}
              node={child}
              depth={depth + 1}
              open={open}
              onToggle={onToggle}
              onOpenFile={onOpenFile}
            />
          ))}
          <Omitted node={node} depth={depth + 1} />
        </ul>
      )}
    </li>
  );
}
