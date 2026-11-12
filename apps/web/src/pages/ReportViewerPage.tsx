import { useQuery } from '@tanstack/react-query';
import { Link, useParams } from 'react-router-dom';
import { api } from '../api/endpoints';
import { ReportButtons } from '../components/ReportButtons';
import { ErrorState, Loading } from '../components/States';

/**
 * The HTML report embeds (escaped) untrusted code. It is fetched with the Bearer token and
 * shown in a fully sandboxed iframe: no scripts, opaque origin, so it can never act as the app.
 */
export function ReportViewerPage() {
  const { scanId = '' } = useParams();
  const html = useQuery({
    queryKey: ['report-html', scanId],
    queryFn: () => api.reportHtml(scanId),
    retry: false,
  });

  return (
    <div className="page page-wide">
      <nav aria-label="Breadcrumb" className="crumbs">
        <Link to={`/scans/${scanId}`}>← Back to scan</Link>
      </nav>
      <div className="page-head">
        <h1>Scan report</h1>
        <ReportButtons scanId={scanId} />
      </div>
      {html.isPending ? (
        <Loading label="Rendering report…" />
      ) : html.isError ? (
        <ErrorState title="Report unavailable" error={html.error} onRetry={() => html.refetch()} />
      ) : (
        <iframe
          title="Scan report"
          className="report-frame"
          sandbox=""
          srcDoc={html.data}
          referrerPolicy="no-referrer"
        />
      )}
    </div>
  );
}
