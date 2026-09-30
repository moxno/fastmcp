/**
 * FastMCP ZTDS Middleware Unit Tests
 * Conforms to IETF draft-sibiryakov-ztds-protocol-00
 */

import { describe, expect, it } from "vitest";

import { ZTDSFastMCPMiddleware } from "./ztdsMiddleware.js";

describe("ZTDSFastMCPMiddleware", () => {
  it("sanitizes input arguments and output responses with crypto tokens", async () => {
    const middleware = new ZTDSFastMCPMiddleware();

    const mockTool = async (
      args: { query: string; token: string },
      context: { unmask?: (val: unknown) => unknown },
    ) => {
      // Tool receives unguessable crypto tokens
      expect(args.query).not.toContain("ceo@enterprise.com");
      expect(args.query).toMatch(/\[EMAIL_TOKEN_[a-f0-9]{8}\]/);
      expect(args.token).not.toContain("sk-proj-abcdef12345678901234567890");
      expect(args.token).toMatch(/\[API_SECRET_TOKEN_[a-f0-9]{8}\]/);

      // Verify bidirectional unmasking in tool context
      const realEmail = context.unmask ? context.unmask(args.query) : "";
      expect(realEmail).toContain("ceo@enterprise.com");

      return {
        message: "Account verified for ceo@enterprise.com",
        query: args.query,
      };
    };

    const wrapped = middleware.wrapTool("authTest", mockTool);
    const result = await wrapped({
      query: "Verify ceo@enterprise.com",
      token: "sk-proj-abcdef12345678901234567890",
    });

    expect(result.message).not.toContain("ceo@enterprise.com");
    expect(result.message).toMatch(/\[EMAIL_TOKEN_[a-f0-9]{8}\]/);
    expect(result._ztds.zeroEgress).toBe(true);
    expect(result._ztds.standard).toContain(
      "draft-sibiryakov-ztds-protocol-00",
    );
  });

  it("supports backward-compatible sequential tokens when useCryptoTokens is false", async () => {
    const middleware = new ZTDSFastMCPMiddleware({ useCryptoTokens: false });
    const res = middleware.sanitizeText(
      "Contact support@enterprise.com and sales@enterprise.com",
      "test-seq",
    );
    expect(res.sanitized).toContain("[EMAIL_TOKEN_1]");
    expect(res.sanitized).toContain("[EMAIL_TOKEN_2]");
  });

  it("handles string tool returns without string-spread key corruption", async () => {
    const middleware = new ZTDSFastMCPMiddleware();
    const wrapped = middleware.wrapTool("stringEcho", async () => {
      return "Alert: contact ceo@enterprise.com immediately.";
    });

    const result = (await wrapped({})) as unknown as {
      _ztds: { zeroEgress: boolean };
      [key: number]: unknown;
      content: Array<{ text: string; type: string }>;
    };

    expect(result[0]).toBeUndefined();
    expect(Array.isArray(result.content)).toBe(true);
    expect(result.content[0].text).not.toContain("ceo@enterprise.com");
    expect(result.content[0].text).toMatch(/\[EMAIL_TOKEN_[a-f0-9]{8}\]/);
    expect(result._ztds.zeroEgress).toBe(true);
  });

  it("preserves standard MCP content array structure", async () => {
    const middleware = new ZTDSFastMCPMiddleware();
    const wrapped = middleware.wrapTool("mcpContent", async () => {
      return {
        content: [
          { text: "Secret email: admin@test.com", type: "text" },
          { data: "base64data==", mimeType: "image/png", type: "image" },
        ],
      };
    });

    const result = (await wrapped({})) as unknown as {
      content: Array<{ data?: string; text?: string; type: string }>;
    };

    expect(result.content.length).toBe(2);
    expect(result.content[0].text).toMatch(/\[EMAIL_TOKEN_[a-f0-9]{8}\]/);
    expect(result.content[0].text).not.toContain("admin@test.com");
    expect(result.content[1].type).toBe("image");
    expect(result.content[1].data).toBe("base64data==");
  });

  it("resists ReDoS on 32 KB pathological payload (<20ms)", () => {
    const middleware = new ZTDSFastMCPMiddleware();
    const payload = "a.".repeat(16000); // 32 KB without @

    const start = performance.now();
    const res = middleware.sanitizeText(payload, "redos-test");
    const elapsed = performance.now() - start;

    expect(res.sanitized).toBe(payload);
    expect(elapsed).toBeLessThan(20);
  });

  it("guarantees volatile RAM zeroization after invocation", async () => {
    const middleware = new ZTDSFastMCPMiddleware();
    const wrapped = middleware.wrapTool(
      "echo",
      async (args: { text: string }) => args,
    );

    await wrapped({ text: "Card 4111-2222-3333-4444" });

    // Internal maps should be completely wiped
    const internal = middleware as unknown as {
      _entityMaps: Map<string, Map<string, string>>;
      _sessionMaps: Map<string, Map<string, string>>;
    };
    expect(internal._sessionMaps.size).toBe(0);
    expect(internal._entityMaps.size).toBe(0);
  });
});
