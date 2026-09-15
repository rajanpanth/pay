import { useMemo, useState } from "react";
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

  return (
    <main className="cloud-page">
      <WelcomeCard
        canContinue={linked}
        submitting={submitting}
        error={error}
        note={
          linked ? undefined : (
            <>
              Open this page from <code>pay setup</code> to link your terminal.
            </>
          )
        }
        onContinue={handleContinue}
      />
      {params.host && (
        <p className="cloud-host">Linking pay on {params.host}</p>
      )}
    </main>
  );
}
