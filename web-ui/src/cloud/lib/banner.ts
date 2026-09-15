/**
 * The pay.sh banner, byte for byte the CLI's `PAY_SH_BANNER`
 * (rust/crates/cli/src/components/banner.rs), with the same vertical
 * white-to-gray gradient so the page opened from `pay setup` looks like the
 * terminal that opened it.
 */
export const PAY_SH_BANNER: readonly string[] = [
  "██████╗  █████╗ ██╗   ██╗   ███████╗██╗  ██╗",
  "██╔══██╗██╔══██╗╚██╗ ██╔╝   ██╔════╝██║  ██║",
  "██████╔╝███████║ ╚████╔╝    ███████╗███████║",
  "██╔═══╝ ██╔══██║  ╚██╔╝     ╚════██║██╔══██║",
  "██║     ██║  ██║   ██║   ██╗███████║██║  ██║",
  "╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝╚══════╝╚═╝  ╚═╝",
];

export const PAY_SH_TAGLINE = "Toolchain for agentic payments";

const GRADIENT_FROM: [number, number, number] = [86, 86, 86];
const GRADIENT_TO: [number, number, number] = [255, 255, 255];

/**
 * Colour of banner row `row` out of `rowCount`: white at the top fading to
 * gray at the bottom, matching the CLI's `gradient_line`.
 */
export function bannerRowColor(row: number, rowCount: number): string {
  const position = rowCount <= 1 ? 1 : 1 - row / (rowCount - 1);
  const channel = (i: number) =>
    Math.round(GRADIENT_FROM[i] + (GRADIENT_TO[i] - GRADIENT_FROM[i]) * position);
  return `rgb(${channel(0)}, ${channel(1)}, ${channel(2)})`;
}
