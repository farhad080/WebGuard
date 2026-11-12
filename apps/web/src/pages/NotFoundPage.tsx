import { Link } from 'react-router-dom';
import { EmptyState } from '../components/States';

export function NotFoundPage() {
  return (
    <div className="page">
      <EmptyState title="Page not found" action={<Link to="/projects">Go to your projects</Link>}>
        The page you were looking for doesn't exist.
      </EmptyState>
    </div>
  );
}
