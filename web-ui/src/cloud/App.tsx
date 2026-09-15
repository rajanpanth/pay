import { useEffect, useMemo, useState } from "react";
import { TerminalLink } from "../components/cloud/TerminalLink";
import { TerminalProgress, type ProgressLine } from "../components/cloud/TerminalProgress";
import { WelcomeCard } from "../components/cloud/WelcomeCard";
import {
  buildProviderStartRequest,
  hasLinkParams,
  parseOnboardParams,
  providerCallbackFromPath,
} from "./lib/onboard";

/** Error body returned by pay-cloud on validation failure. */
interface ApiError {
  error?: string;
  message?: string;
}

async function postJson<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const json = (await res.json().catch(() => ({}))) as ApiError & T;
  if (!res.ok) {
    throw new Error(json.message ?? `Request failed (${res.status})`);
  }
  return json;
}

export function App() {
  const params = useMemo(() => parseOnboardParams(window.location.search), []);
  const linked = hasLinkParams(params);
  const callbackProvider = useMemo(
    () => providerCallbackFromPath(window.location.pathname),
    [],
  );
  const terminal = linked || callbackProvider !== null;

  useEffect(() => {
    document.documentElement.dataset.cloudTheme = terminal ? "terminal" : "light";
  }, [terminal]);

  if (callbackProvider) {
    return (
      <main className="cloud-page cloud-page--terminal">
        <ProviderCallback provider={callbackProvider} />
      </main>
    );
  }

  if (linked) {
    return (
      <main className="cloud-page cloud-page--terminal">
        <LinkFlow params={params} />
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

/** Step 1: the user picks a provider; we open a session and hand off. */
function LinkFlow({ params }: { params: ReturnType<typeof parseOnboardParams> }) {
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleContinue(provider: string) {
    if (!hasLinkParams(params)) return;
    setBusy(provider);
    setError(null);
    try {
      const res = await postJson<{ consent?: string }>(
        "/api/onboard/start",
        buildProviderStartRequest(params, provider),
      );
      if (!res.consent) throw new Error("The server did not return a sign-in link.");
      window.location.assign(res.consent);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong.");
      setBusy(null);
    }
  }

  return <TerminalLink params={params} busy={busy} error={error} onContinue={handleContinue} />;
}

/**
 * Step 2: the provider redirected back with the grant in the URL fragment.
 * Post it to the server, which provisions the wallet, then follow the
 * redirect to the CLI. The fragment never travels in a URL we log.
 */
function ProviderCallback({ provider }: { provider: string }) {
  const [lines, setLines] = useState<ProgressLine[]>([
    { text: `Signed in with ${provider}`, state: "done" },
    { text: "Creating your wallet", state: "active" },
  ]);

  useEffect(() => {
    let cancelled = false;
    const fragment = window.location.hash;
    // Drop the secrets from the address bar and history right away.
    window.history.replaceState(null, "", window.location.pathname);

    (async () => {
      try {
        if (!fragment || fragment.length < 2) {
          throw new Error("The provider did not return a sign-in result. Run pay setup again.");
        }
        const res = await postJson<{ redirect: string; address: string }>(
          `/api/onboard/${provider}/complete`,
          { fragment },
        );
        if (cancelled) return;
        setLines([
          { text: `Signed in with ${provider}`, state: "done" },
          { text: `Wallet created: ${res.address}`, state: "done" },
          { text: "Returning to your terminal", state: "active" },
        ]);
        window.location.assign(res.redirect);
      } catch (err) {
        if (cancelled) return;
        setLines([
          { text: `Signed in with ${provider}`, state: "done" },
          {
            text: err instanceof Error ? err.message : "Something went wrong.",
            state: "error",
          },
          { text: "Return to your terminal and run pay setup again.", state: "error" },
        ]);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [provider]);

  return <TerminalProgress title={`pay setup --backend cloud`} lines={lines} />;
}
