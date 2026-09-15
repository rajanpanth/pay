import type { ReactNode } from "react";

interface Props {
  /** Window title, e.g. `pay setup — ludo@host`. */
  title: string;
  children: ReactNode;
}

/** A terminal window: traffic-light header, hairline border, dark body. */
export function TerminalFrame({ title, children }: Props) {
  return (
    <section className="cloud-term" aria-label={title}>
      <header className="cloud-term-head">
        <span className="cloud-term-dots" aria-hidden="true">
          <i className="cloud-term-dot cloud-term-dot--red" />
          <i className="cloud-term-dot cloud-term-dot--yellow" />
          <i className="cloud-term-dot cloud-term-dot--green" />
        </span>
        <span className="cloud-term-title">{title}</span>
      </header>
      <div className="cloud-term-body">{children}</div>
    </section>
  );
}
