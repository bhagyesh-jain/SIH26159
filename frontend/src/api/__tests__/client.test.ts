import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { buildUrl, apiGet, ApiError } from "../client";

describe("API Client Utility Tests", () => {
  const originalFetch = global.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it("1. API client builds URL correctly with query parameters", () => {
    const url = buildUrl("/api/v1/findings", {
      severity: "CRITICAL",
      protocol: "SMTP",
      limit: 50,
      offset: 0,
    });
    expect(url).toContain("/api/v1/findings");
    expect(url).toContain("severity=CRITICAL");
    expect(url).toContain("protocol=SMTP");
    expect(url).toContain("limit=50");
    expect(url).toContain("offset=0");
  });

  it("2. FastAPI detail error messages are extracted and surfaced in ApiError", async () => {
    const mockResponse = {
      ok: false,
      status: 404,
      statusText: "Not Found",
      json: async () => ({ detail: "Investigation case not found." }),
    };

    global.fetch = vi.fn().mockResolvedValue(mockResponse as unknown as Response);

    await expect(apiGet("/api/v1/investigations/inv_missing")).rejects.toThrow(
      "Investigation case not found."
    );

    try {
      await apiGet("/api/v1/investigations/inv_missing");
    } catch (err: unknown) {
      expect(err).toBeInstanceOf(ApiError);
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(404);
      expect(apiErr.detail).toBe("Investigation case not found.");
    }
  });

  it("4. Query parameters with undefined or null values are omitted", () => {
    const url = buildUrl("/api/v1/security-events", {
      protocol: "IMAP",
      event_type: undefined,
      upgrade_status: null,
      limit: 100,
    });
    expect(url).toContain("protocol=IMAP");
    expect(url).toContain("limit=100");
    expect(url).not.toContain("event_type");
    expect(url).not.toContain("upgrade_status");
  });
});
