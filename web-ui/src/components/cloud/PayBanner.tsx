import { PAY_SH_BANNER, PAY_SH_TAGLINE, bannerRowColor } from "../../cloud/lib/banner";

/** Cell kinds derived from the banner glyphs. */
function cellClass(glyph: string): string | null {
  if (glyph === "█") return "cloud-term-cell cloud-term-cell--block";
  if (glyph === " ") return null;
  // ╗╔╝╚═║ — the shadow the terminal draws around the letters.
  return "cloud-term-cell cloud-term-cell--frame";
}

/**
 * The pay.sh ASCII banner drawn as a grid of cells, one per character, so
 * it renders identically whether or not the viewer's monospace font has
 * block-element glyphs. Colours follow the CLI's vertical gradient.
 */
export function PayBanner() {
  const columns = [...PAY_SH_BANNER[0]].length;
  return (
    <div className="cloud-term-banner" role="img" aria-label="pay.sh">
      <div
        className="cloud-term-art"
        style={{ gridTemplateColumns: `repeat(${columns}, var(--term-cell-w))` }}
      >
        {PAY_SH_BANNER.map((row, r) => {
          const color = bannerRowColor(r, PAY_SH_BANNER.length);
          return [...row].map((glyph, c) => {
            const className = cellClass(glyph);
            return (
              <span
                key={`${r}-${c}`}
                className={className ?? "cloud-term-cell"}
                style={className ? { color } : undefined}
              />
            );
          });
        })}
      </div>
      <div className="cloud-term-tagline">{PAY_SH_TAGLINE}</div>
    </div>
  );
}
