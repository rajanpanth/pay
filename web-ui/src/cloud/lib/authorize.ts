/**
 * Pure helpers for the OAuth consent page (`/authorize?request=…`).
 *
 * pay-cloud's `/oauth/authorize` validates an MCP host's request, parks it,
 * and sends the browser here. The page shows who is asking, and Approve or
 * Deny posts the decision back; the server answers with where to send the
 * browser next (the host's redirect URI with a code, or an error).
 */

/** What `GET /api/oauth/authorize/{request}` returns. */
export interface PendingView {
  client_name: string;
  redirect_host: string;
  scope: string;
}

/** What Approve and Deny return. */
export interface Decision {
  redirect: string;
}

/** `/authorize` or `/authorize/` and nothing else. */
export function isAuthorizePath(pathname: string): boolean {
  return /^\/authorize\/?$/.test(pathname);
}

/** The pending request id from `?request=…`, or null. */
export function parseAuthorizeRequest(search: string): string | null {
  const v = new URLSearchParams(search).get("request");
  return v && /^[A-Za-z0-9_-]{16,128}$/.test(v) ? v : null;
}

/** Human wording for a scope. */
export function describeScope(scope: string): string {
  return scope
    .split(/\s+/)
    .filter(Boolean)
    .map((s) =>
      s === "mcp"
        ? "use the pay tools and pay for API calls from your account"
        : `use the ${s} scope`,
    )
    .join("; ");
}
