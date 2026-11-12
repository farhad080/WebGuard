import { useQuery } from '@tanstack/react-query';
import type { Finding } from '@webguard/core';
import { Link, useParams } from 'react-router-dom';
import { api } from '../api/endpoints';
import {
  ConfidenceBadge,
  CweBadge,
  OwaspBadge,
  ReviewBadges,
  SeverityBadge,
} from '../components/Badges';
import { CodeView } from '../components/code/CodeView';
import { CopyButton } from '../components/CopyButton';
import { ErrorState, Loading } from '../components/States';
import { Tabs } from '../components/Tabs';
import { confidenceBand, isCandidate } from '../lib/findings';

function ExplanationTab({ finding }: { finding: Finding }) {
  return (
    <div className="prose">
      <p>{finding.explanation}</p>
      {finding.remediation?.why && finding.remediation.why !== finding.explanation && (
        <p>{finding.remediation.why}</p>
      )}
      {finding.evidence.length > 0 && (
        <>
          <h3>Evidence</h3>
          <ul>
            {finding.evidence.map((e, i) => (
              <li key={i}>{e}</li>
            ))}
          </ul>
        </>
      )}
      <h3>Detected by</h3>
      <p className="mono small">
        {(finding.contributingDetectors.length
          ? finding.contributingDetectors
          : [finding.detectorId]
        ).join(', ')}
      </p>
    </div>
  );
}

function ImpactTab({ finding }: { finding: Finding }) {
  const r = finding.remediation;
  return (
    <div className="prose">
      {r ? (
        <>
          <h3>How it is exploited</h3>
          <p>{r.why}</p>
          <h3>Impact</h3>
          <p>{r.impact}</p>
        </>
      ) : (
        <p className="muted">No exploit/impact write-up is stored for this finding.</p>
      )}
    </div>
  );
}

function FixTab({ finding }: { finding: Finding }) {
  const r = finding.remediation;
  if (!r) {
    return (
      <div className="prose">
        <p>{finding.fixSuggestion}</p>
      </div>
    );
  }
  const ex = r.secureExample;
  return (
    <div className="prose">
      <h3>{r.title}</h3>
      <ol className="fix-steps">
        {r.steps.map((s, i) => (
          <li key={i}>{s}</li>
        ))}
      </ol>
      <h3>
        Secure example{' '}
        <span className="badge badge-neutral">
          {ex.contextualized ? 'rewritten from your code' : 'generic template'}
        </span>
      </h3>
      <div className="before-after">
        <figure>
          <figcaption>
            <span className="ba-label ba-before">Before (vulnerable)</span>
          </figcaption>
          <pre className="snippet">
            <code>{ex.before}</code>
          </pre>
        </figure>
        <figure>
          <figcaption>
            <span className="ba-label ba-after">After (secure)</span>
            <CopyButton text={ex.after} label="Copy secure code" />
          </figcaption>
          <pre className="snippet">
            <code>{ex.after}</code>
          </pre>
        </figure>
      </div>
      {ex.note && (
        <p className="notice small">
          <strong>Note:</strong> {ex.note}
        </p>
      )}
      {r.references.length > 0 && (
        <>
          <h3>References</h3>
          <ul>
            {r.references.map((ref) => (
              <li key={ref.url}>
                <a href={ref.url} target="_blank" rel="noreferrer noopener">
                  {ref.title}
                </a>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}

export function FindingPage() {
  const { findingId = '' } = useParams();
  const finding = useQuery({
    queryKey: ['finding', findingId],
    queryFn: () => api.getFinding(findingId),
  });

  if (finding.isPending) return <Loading label="Loading finding…" />;
  if (finding.isError) return <ErrorState title="Finding unavailable" error={finding.error} />;

  const f = finding.data;
  const candidate = isCandidate(f);
  const low = confidenceBand(f.confidence) === 'low';

  return (
    <div className="page">
      <nav aria-label="Breadcrumb" className="crumbs">
        <Link to="/projects">Projects</Link> <span aria-hidden="true">/</span>{' '}
        <Link to={`/scans/${f.scanId}`}>Scan</Link> <span aria-hidden="true">/</span>{' '}
        <span aria-current="page">Finding</span>
      </nav>
      <h1 className="finding-title">{f.remediation?.title ?? f.explanation.split('. ')[0]}</h1>
      <div className="badge-row" data-testid="finding-badges">
        <SeverityBadge severity={f.severity} />
        <ConfidenceBadge confidence={f.confidence} />
        <OwaspBadge category={f.owaspCategory} />
        <CweBadge cwe={f.cwe} />
        <ReviewBadges finding={f} />
      </div>
      {(candidate || low) && (
        <p className="notice" role="note">
          {candidate
            ? 'Candidate finding: this comes from a route-level heuristic. Confirm it manually before treating it as a vulnerability.'
            : 'Low-confidence finding: the detector could not prove the data flow end to end. Verify before acting.'}
        </p>
      )}

      <div className="finding-layout">
        <CodeView
          scanId={f.scanId}
          path={f.filePath}
          lineStart={f.lineStart}
          lineEnd={f.lineEnd}
          fallbackSnippet={f.snippet}
        />
        <Tabs
          label="Finding details"
          tabs={[
            { id: 'explanation', label: 'Explanation', content: <ExplanationTab finding={f} /> },
            { id: 'impact', label: 'Exploit / Impact', content: <ImpactTab finding={f} /> },
            { id: 'fix', label: 'Fix', content: <FixTab finding={f} /> },
          ]}
        />
      </div>
    </div>
  );
}
