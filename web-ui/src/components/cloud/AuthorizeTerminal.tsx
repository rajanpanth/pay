import { useEffect, useState } from "react";
import { describeScope, type Decision, type PendingView } from "../../cloud/lib/authorize";
import { PayWordmark } from "./PayWordmark";

interface Props {
  /** Pending request id from the URL, or null when missing/malformed. */
  requestId: string | null;
  load: (requestId: string) => Promise<PendingView>;
  approve: (requestId: string) => Promise<Decision>;
  deny: (requestId: string) => Promise<Decision>;
}

type Phase =
  | { kind: "loading" }
  | { kind: "ready"; view: PendingView }
  | { kind: "deciding"; view: PendingView; choice: "approve" | "deny" }
  | { kind: "redirecting"; choice: "approve" | "deny" }
  | { kind: "error"; message: string };

/**
 * The OAuth consent screen: an MCP host asked to use this pay account.
 * Approve sends the browser back to the host with a code; Deny sends it
 * back with an error. Nothing else happens on this page.
 */
export function AuthorizeTerminal({ requestId, load, approve, deny }: Props) {
  const [phase, setPhase] = useState<Phase>(
    requestId
      ? { kind: "loading" }
      : { kind: "error", message: "This link is missing its request. Start again from your MCP client." },
  );

  useEffect(() => {
    if (!requestId) return;
    let cancelled = false;
    load(requestId)
      .then((view) => !cancelled && setPhase({ kind: "ready", view }))
      .catch((err) => {
        if (cancelled) return;
        setPhase({
          kind: "error",
          message: err instanceof Error ? err.message : "Something went wrong.",
        });
      });
    return () => {
      cancelled = true;
    };
  }, [requestId, load]);

  async function decide(view: PendingView, choice: "approve" | "deny") {
    if (!requestId) return;
    setPhase({ kind: "deciding", view, choice });
    try {
      const decision = await (choice === "approve" ? approve(requestId) : deny(requestId));
      setPhase({ kind: "redirecting", choice });
      window.location.assign(decision.redirect);
    } catch (err) {
      setPhase({
        kind: "error",
        message: err instanceof Error ? err.message : "Something went wrong.",
      });
    }
  }

  return (
    <section className="cloud-term" aria-label="Authorize an MCP client">
      <div className="cloud-term-banner">
        <PayWordmark />
        <div className="cloud-term-tagline">Toolchain for agentic payments</div>
      </div>

      <div className="cloud-term-lines">
        <div className="cloud-term-line">
          <span className="cloud-term-prompt">$</span> pay connect
        </div>

        {phase.kind === "loading" && (
          <div className="cloud-term-line cloud-term-line--muted">… loading the request</div>
        )}

        {(phase.kind === "ready" || phase.kind === "deciding") && (
          <>
            <div className="cloud-term-line">
              <span className="cloud-term-prompt">›</span>{" "}
              <strong>{phase.view.client_name}</strong> wants to connect to your pay account.
            </div>
            <div className="cloud-term-line cloud-term-line--muted">
              It will be able to {describeScope(phase.view.scope)}. Every paid call is checked
              against your limits, and you can revoke this access at any time.
            </div>
            {phase.view.redirect_host && (
              <div className="cloud-term-line cloud-term-line--muted">
                After you decide, you return to {phase.view.redirect_host}.
              </div>
            )}
            <div className="cloud-term-actions">
              <button
                type="button"
                className="cloud-term-button"
                disabled={phase.kind === "deciding"}
                onClick={() => decide(phase.view, "approve")}
              >
                {phase.kind === "deciding" && phase.choice === "approve" ? "Approving…" : "Approve"}
              </button>
              <button
                type="button"
                className="cloud-term-button cloud-term-button--ghost"
                disabled={phase.kind === "deciding"}
                onClick={() => decide(phase.view, "deny")}
              >
                {phase.kind === "deciding" && phase.choice === "deny" ? "Denying…" : "Deny"}
              </button>
            </div>
          </>
        )}

        {phase.kind === "redirecting" && (
          <div className="cloud-term-line cloud-term-line--muted">
            {phase.choice === "approve" ? "✔ Approved." : "✖ Denied."} Returning to your MCP
            client…
          </div>
        )}

        {phase.kind === "error" && (
          <div className="cloud-term-line cloud-term-line--error" role="alert">
            error: {phase.message}
          </div>
        )}
      </div>
    </section>
  );
}
