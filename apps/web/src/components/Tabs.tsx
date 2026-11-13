import { useId, useRef, useState, type KeyboardEvent, type ReactNode } from 'react';

export interface TabDef {
  id: string;
  label: string;
  content: ReactNode;
}

/** WAI-ARIA tabs: roving tabindex, Left/Right/Home/End move focus and selection. */
export function Tabs({
  tabs,
  label,
  initial,
  active: controlled,
  onChange,
}: {
  tabs: TabDef[];
  label: string;
  initial?: string;
  /** Controlled selection (e.g. kept in the URL); falls back to internal state. */
  active?: string;
  onChange?: (id: string) => void;
}) {
  const [own, setOwn] = useState(initial ?? tabs[0]?.id);
  const active = controlled ?? own;
  const setActive = (id: string) => {
    setOwn(id);
    onChange?.(id);
  };
  const baseId = useId();
  const refs = useRef<(HTMLButtonElement | null)[]>([]);

  const onKeyDown = (e: KeyboardEvent, index: number) => {
    let next = index;
    if (e.key === 'ArrowRight') next = (index + 1) % tabs.length;
    else if (e.key === 'ArrowLeft') next = (index - 1 + tabs.length) % tabs.length;
    else if (e.key === 'Home') next = 0;
    else if (e.key === 'End') next = tabs.length - 1;
    else return;
    e.preventDefault();
    setActive(tabs[next]!.id);
    refs.current[next]?.focus();
  };

  return (
    <div className="tabs">
      <div role="tablist" aria-label={label} className="tablist">
        {tabs.map((t, i) => (
          <button
            key={t.id}
            ref={(el) => {
              refs.current[i] = el;
            }}
            type="button"
            role="tab"
            id={`${baseId}-tab-${t.id}`}
            aria-selected={active === t.id}
            aria-controls={`${baseId}-panel-${t.id}`}
            tabIndex={active === t.id ? 0 : -1}
            onClick={() => setActive(t.id)}
            onKeyDown={(e) => onKeyDown(e, i)}
          >
            {t.label}
          </button>
        ))}
      </div>
      {tabs.map((t) => (
        <div
          key={t.id}
          role="tabpanel"
          id={`${baseId}-panel-${t.id}`}
          aria-labelledby={`${baseId}-tab-${t.id}`}
          hidden={active !== t.id}
          tabIndex={0}
          className="tabpanel"
        >
          {active === t.id && t.content}
        </div>
      ))}
    </div>
  );
}
