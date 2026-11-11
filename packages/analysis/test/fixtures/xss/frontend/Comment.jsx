// React DOM XSS: the URL fragment goes straight into dangerouslySetInnerHTML.
export function Comment() {
  const fragment = window.location.hash.slice(1);
  return <div className="comment" dangerouslySetInnerHTML={{ __html: decodeURIComponent(fragment) }} />;
}
