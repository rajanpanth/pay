import { useEffect, useMemo, useState } from "react";
import { TerminalLink } from "../components/cloud/TerminalLink";
import { WelcomeCard } from "../components/cloud/WelcomeCard";
import {
  buildStartRequest,
  hasLinkParams,
  parseOnboardParams,
} from "./lib/onboard";

/** Error body returned by pay-cloud on validation failure. */
interface ApiError {
  error?: string;
  message?: string;
}

export function App() {
  const params = useMemo(() => parseOnboardParams(window.location.search), []);
  const linked = hasLinkParams(params);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Opened from `pay setup`: dress the page like the terminal that opened
  // it. Opened directly: the plain light card.
  useEffect(() => {
    document.documentElement.dataset.cloudTheme = linked ? "terminal" : "light";
  }, [linked]);

  async function handleContinue(email: string) {
    if (!linked) return;
    setSubmitting(true);
    setError(null);
    try {
      const res = await fetch("/api/onboard/start", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(buildStartRequest(params, email)),
      });
      const body = (await res.json().catch(() => ({}))) as ApiError & { redirect?: string };
      if (!res.ok || !body.redirect) {
        throw new Error(body.message ?? `Request failed (${res.status})`);
      }
      window.location.assign(body.redirect);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong.");
      setSubmitting(false);
    }
  }

  if (linked) {
    return (
      <main className="cloud-page cloud-page--terminal">
        <TerminalLink
          params={params}
          submitting={submitting}
          error={error}
          onContinue={handleContinue}
        />
      </main>
    );
  }

  return (
    <main className="cloud-page">
      <WelcomeCard
        canContinue={false}
        submitting={false}
        error={null}
        note={
          <>
            Open this page from <code>pay setup</code> to link your terminal.
          </>
        }
        onContinue={() => undefined}
      />
    </main>
  );
}
