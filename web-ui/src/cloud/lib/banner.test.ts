import { describe, expect, it } from "vitest";
import { PAY_SH_BANNER, bannerRowColor } from "./banner";

describe("PAY_SH_BANNER", () => {
  it("is the six-row CLI banner with equal-width rows", () => {
    expect(PAY_SH_BANNER).toHaveLength(6);
    const widths = new Set(PAY_SH_BANNER.map((row) => [...row].length));
    expect(widths.size).toBe(1);
  });

  it("uses only block and box-drawing glyphs plus spaces", () => {
    for (const row of PAY_SH_BANNER) {
      expect(row).toMatch(/^[█╗╔╝╚═║ ]+$/u);
    }
  });
});

describe("bannerRowColor", () => {
  it("fades from white at the top to gray at the bottom like the CLI", () => {
    expect(bannerRowColor(0, 6)).toBe("rgb(255, 255, 255)");
    expect(bannerRowColor(5, 6)).toBe("rgb(86, 86, 86)");
  });

  it("treats a single row as white", () => {
    expect(bannerRowColor(0, 1)).toBe("rgb(255, 255, 255)");
  });
});
