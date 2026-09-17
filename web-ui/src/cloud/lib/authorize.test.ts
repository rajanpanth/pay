import { describe, expect, it } from "vitest";
import { describeScope, isAuthorizePath, parseAuthorizeRequest } from "./authorize";

describe("authorize helpers", () => {
  it("matches only the consent page path", () => {
    expect(isAuthorizePath("/authorize")).toBe(true);
    expect(isAuthorizePath("/authorize/")).toBe(true);
    expect(isAuthorizePath("/oauth/authorize")).toBe(false);
    expect(isAuthorizePath("/authorized")).toBe(false);
  });

  it("reads a well-formed request id and rejects junk", () => {
    const id = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    expect(parseAuthorizeRequest(`?request=${id}`)).toBe(id);
    expect(parseAuthorizeRequest("?request=short")).toBeNull();
    expect(parseAuthorizeRequest("?request=has%20space%20and%20more%20chars")).toBeNull();
    expect(parseAuthorizeRequest("")).toBeNull();
  });

  it("describes the mcp scope in plain words", () => {
    expect(describeScope("mcp")).toContain("pay for API calls");
    expect(describeScope("mcp other")).toContain("other scope");
  });
});
