import type { InformationalNote } from '@webguard/core';

/**
 * Weakness classes source analysis cannot detect reliably (policy, runtime behavior,
 * discovery). Deliberately styled apart from findings: they are not results and carry no
 * severity — they are a manual review checklist.
 */
export function InformationalNotes({ notes }: { notes: InformationalNote[] }) {
  if (notes.length === 0) return null;
  return (
    <section className="info-notes" aria-labelledby="info-notes-title">
      <h2 id="info-notes-title">
        <span aria-hidden="true">ⓘ</span> Informational — review manually
      </h2>
      <p className="muted">
        Not findings. These challenge classes can't be confirmed from source code alone, so they are
        listed for manual or dynamic testing instead of being silently dropped.
      </p>
      <ul>
        {notes.map((n) => (
          <li key={n.id}>
            <details>
              <summary>
                <strong>{n.title}</strong>
                {n.references.length > 0 && (
                  <span className="muted"> · {n.references.join(', ')}</span>
                )}
              </summary>
              <p>{n.note}</p>
            </details>
          </li>
        ))}
      </ul>
    </section>
  );
}
