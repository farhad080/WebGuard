// SAFE: React escapes {text}; the HTML path is sanitized with DOMPurify. No findings.
import DOMPurify from 'dompurify';

export function SafeComment({ text }) {
  const html = window.location.hash.slice(1);
  return (
    <div>
      <p>{text}</p>
      <p>{window.location.search}</p>
      <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />
    </div>
  );
}
