import { useRef, useState, type DragEvent } from 'react';

const ZIP_TYPES = [
  'application/zip',
  'application/x-zip-compressed',
  'application/x-zip',
  'application/octet-stream',
  '',
];

export function isZipFile(file: File): boolean {
  return file.name.toLowerCase().endsWith('.zip') && ZIP_TYPES.includes(file.type);
}

/**
 * Drag-and-drop ZIP picker. The drop area is also a real <label>/<input type="file">, so it
 * works by keyboard and screen reader, not just by dragging.
 */
export function Dropzone({
  onFile,
  disabled,
  progress,
  error,
}: {
  onFile: (file: File) => void;
  disabled?: boolean;
  /** 0–1 while uploading. */
  progress?: number | null;
  error?: string | null;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);

  const accept = (file: File | undefined) => {
    if (!file) return;
    if (!isZipFile(file)) {
      setLocalError(`"${file.name}" is not a .zip file.`);
      return;
    }
    setLocalError(null);
    onFile(file);
  };

  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setDragging(false);
    if (disabled) return;
    accept(e.dataTransfer.files[0]);
  };

  const shownError = localError ?? error;
  const uploading = progress !== null && progress !== undefined;

  return (
    <div>
      <label
        className={`dropzone${dragging ? ' dragging' : ''}${disabled ? ' disabled' : ''}`}
        onDragOver={(e) => {
          e.preventDefault();
          if (!disabled) setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        data-testid="dropzone"
      >
        <input
          ref={inputRef}
          type="file"
          accept=".zip,application/zip"
          className="visually-hidden"
          disabled={disabled}
          aria-describedby="dropzone-help"
          onChange={(e) => {
            accept(e.target.files?.[0]);
            e.target.value = '';
          }}
        />
        <span className="dropzone-icon" aria-hidden="true">
          ⇪
        </span>
        <span className="dropzone-title">
          {uploading ? 'Uploading…' : 'Drop a project ZIP here, or click to choose'}
        </span>
        <span id="dropzone-help" className="muted">
          Source only — WebGuard never runs your code. Max 50 MB.
        </span>
      </label>
      {uploading && (
        <div className="progress-row">
          <progress max={1} value={progress} aria-label="Upload progress" />
          <span>{Math.round(progress * 100)}%</span>
        </div>
      )}
      {shownError && (
        <p className="field-error" role="alert">
          {shownError}
        </p>
      )}
    </div>
  );
}
