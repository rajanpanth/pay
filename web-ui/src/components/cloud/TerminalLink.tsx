import { useId, useState, type FormEvent } from "react";
import { isValidEmail, type OnboardParams } from "../../cloud/lib/onboard";
import { PayWordmark } from "./PayWordmark";

interface Props {
  params: OnboardParams;
  submitting: boolean;
  error: string | null;
  onContinue: (email: string) => void;
}

/**
 * The onboarding form shown when the page was opened by `pay setup`: a
 * full-screen terminal with the pay.sh wordmark, the command that opened
 * it, and an email prompt.
 */
export function TerminalLink({ params, submitting, error, onContinue }: Props) {
  const [email, setEmail] = useState("");
  const id = useId();
  const enabled = isValidEmail(email) && !submitting;
  const who = [params.account, params.host].filter(Boolean).join("@");

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (enabled) onContinue(email);
  }

  return (
    <section className="cloud-term" aria-label="pay setup">
      <div className="cloud-term-banner">
        <PayWordmark />
        <div className="cloud-term-tagline">Toolchain for agentic payments</div>
      </div>

      <div className="cloud-term-lines">
        <div className="cloud-term-line">
          <span className="cloud-term-prompt">$</span> pay setup --backend cloud
        </div>
        <div className="cloud-term-line cloud-term-line--muted">
          Linking {who || "this terminal"}
          {params.cli ? ` · pay ${params.cli}` : ""}
        </div>
      </div>

      <form className="cloud-term-form" onSubmit={handleSubmit} noValidate>
        <label className="cloud-term-line cloud-term-field" htmlFor={id}>
          <span className="cloud-term-prompt cloud-term-prompt--field">Email ›</span>
          <input
            id={id}
            className="cloud-term-input"
            type="email"
            name="email"
            autoComplete="email"
            autoCapitalize="none"
            spellCheck={false}
            autoFocus
            placeholder="you@example.com"
            value={email}
            disabled={submitting}
            onChange={(e) => setEmail(e.target.value)}
          />
        </label>
        <div className="cloud-term-actions">
          <button
            type="submit"
            className="cloud-term-button"
            disabled={!enabled}
            aria-disabled={!enabled}
          >
            {submitting ? "Linking…" : "Continue"}
          </button>
          <span className="cloud-term-hint">
            Log in or sign up. Your terminal is waiting for this page.
          </span>
        </div>
        {error && (
          <div className="cloud-term-line cloud-term-line--error" role="alert">
            error: {error}
          </div>
        )}
      </form>
    </section>
  );
}
