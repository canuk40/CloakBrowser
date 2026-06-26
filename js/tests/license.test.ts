import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

import {
  resolveLicenseKey,
  validateLicense,
  getProLatestVersion,
} from "../src/license.js";

import * as config from "../src/config.js";

let tmpDir: string;

beforeEach(() => {
  tmpDir = path.join("/tmp", `cloakbrowser-test-${Date.now()}`);
  fs.mkdirSync(tmpDir, { recursive: true });
  vi.spyOn(config, "getCacheDir").mockReturnValue(tmpDir);
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  try {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  } catch {}
});

// ── resolveLicenseKey ─────────────────────────────────

describe("resolveLicenseKey", () => {
  it("explicit param wins over env", () => {
    process.env.CLOAKBROWSER_LICENSE_KEY = "env-key";
    expect(resolveLicenseKey("explicit")).toBe("explicit");
    delete process.env.CLOAKBROWSER_LICENSE_KEY;
  });

  it("env var fallback", () => {
    process.env.CLOAKBROWSER_LICENSE_KEY = "env-key";
    expect(resolveLicenseKey()).toBe("env-key");
    delete process.env.CLOAKBROWSER_LICENSE_KEY;
  });

  it("returns undefined when absent", () => {
    delete process.env.CLOAKBROWSER_LICENSE_KEY;
    expect(resolveLicenseKey()).toBeUndefined();
  });

  it("file fallback when no param or env", () => {
    delete process.env.CLOAKBROWSER_LICENSE_KEY;
    const keyFile = path.join(tmpDir, "license.key");
    fs.writeFileSync(keyFile, "file-key-123\n");
    expect(resolveLicenseKey()).toBe("file-key-123");
  });

  it("env takes precedence over file", () => {
    process.env.CLOAKBROWSER_LICENSE_KEY = "env-key";
    const keyFile = path.join(tmpDir, "license.key");
    fs.writeFileSync(keyFile, "file-key");
    expect(resolveLicenseKey()).toBe("env-key");
    delete process.env.CLOAKBROWSER_LICENSE_KEY;
  });

  it("returns undefined when file missing", () => {
    delete process.env.CLOAKBROWSER_LICENSE_KEY;
    expect(resolveLicenseKey()).toBeUndefined();
  });
});

// ── validateLicense ───────────────────────────────────

describe("validateLicense", () => {
  const keySha = crypto.createHash("sha256").update("test-key").digest("hex");

  it("fresh cache skips server call", async () => {
    const cachePath = path.join(tmpDir, ".license_cache");
    fs.writeFileSync(
      cachePath,
      JSON.stringify({
        key_sha256: keySha,
        valid: true,
        plan: "team",
        expires: "2026-12-01",
        validated_at: Date.now() / 1000,
      })
    );

    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const result = await validateLicense("test-key");

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(result).not.toBeNull();
    expect(result!.valid).toBe(true);
    expect(result!.plan).toBe("team");
  });

  it("stale cache triggers server call", async () => {
    const cachePath = path.join(tmpDir, ".license_cache");
    fs.writeFileSync(
      cachePath,
      JSON.stringify({
        key_sha256: keySha,
        valid: true,
        plan: "solo",
        expires: null,
        validated_at: Date.now() / 1000 - 90000, // 25 hours ago
      })
    );

    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: async () => ({ valid: true, plan: "solo", expires: null }),
    } as Response);

    const result = await validateLicense("test-key");
    expect(globalThis.fetch).toHaveBeenCalledOnce();
    expect(result!.valid).toBe(true);
  });

  it("server success returns LicenseInfo", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: async () => ({ valid: true, plan: "business", expires: "2026-07-13" }),
    } as Response);

    const result = await validateLicense("pro-key");
    expect(result).not.toBeNull();
    expect(result!.valid).toBe(true);
    expect(result!.plan).toBe("business");
    expect(result!.expires).toBe("2026-07-13");
  });

  it("server rejection returns invalid", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: async () => ({ valid: false, plan: "solo", expires: null }),
    } as Response);

    const result = await validateLicense("bad-key");
    expect(result).not.toBeNull();
    expect(result!.valid).toBe(false);
  });

  it("server unreachable uses stale cache", async () => {
    const cachePath = path.join(tmpDir, ".license_cache");
    fs.writeFileSync(
      cachePath,
      JSON.stringify({
        key_sha256: keySha,
        valid: true,
        plan: "solo",
        expires: "2026-12-01",
        validated_at: Date.now() / 1000 - 90000,
      })
    );

    vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("timeout"));

    const result = await validateLicense("test-key");
    expect(result).not.toBeNull();
    expect(result!.valid).toBe(true);
  });

  it("server unreachable no cache returns null", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("timeout"));

    const result = await validateLicense("test-key");
    expect(result).toBeNull();
  });

  it("cache stores hash not raw key", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: async () => ({ valid: true, plan: "solo", expires: null }),
    } as Response);

    await validateLicense("secret-key-123");

    const cachePath = path.join(tmpDir, ".license_cache");
    const content = fs.readFileSync(cachePath, "utf-8");
    expect(content).not.toContain("secret-key-123");
    const expectedSha = crypto
      .createHash("sha256")
      .update("secret-key-123")
      .digest("hex");
    expect(content).toContain(expectedSha);
  });

  it("wrong key cache ignored", async () => {
    const cachePath = path.join(tmpDir, ".license_cache");
    fs.writeFileSync(
      cachePath,
      JSON.stringify({
        key_sha256: "other-hash",
        valid: true,
        plan: "solo",
        expires: null,
        validated_at: Date.now() / 1000,
      })
    );

    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: async () => ({ valid: true, plan: "solo", expires: null }),
    } as Response);

    await validateLicense("different-key");
    expect(globalThis.fetch).toHaveBeenCalledOnce();
  });

  it("expired license rejected from cache", async () => {
    const cachePath = path.join(tmpDir, ".license_cache");
    const keySha = crypto.createHash("sha256").update("test-key").digest("hex");
    fs.writeFileSync(
      cachePath,
      JSON.stringify({
        key_sha256: keySha,
        valid: true,
        plan: "solo",
        expires: "2020-01-01T00:00:00+00:00",
        validated_at: Date.now() / 1000,
      })
    );

    const result = await validateLicense("test-key");
    expect(result).not.toBeNull();
    expect(result!.valid).toBe(false);
  });

  it("does not cache invalid responses", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: async () => ({ valid: false, plan: "solo", expires: null }),
    } as Response);

    await validateLicense("bad-key");

    const cachePath = path.join(tmpDir, ".license_cache");
    expect(fs.existsSync(cachePath)).toBe(false);
  });

  it("corrupted validated_at is treated as absent cache, not trusted", async () => {
    const keySha = crypto.createHash("sha256").update("test-key").digest("hex");
    fs.writeFileSync(
      path.join(tmpDir, ".license_cache"),
      JSON.stringify({
        key_sha256: keySha,
        valid: true,
        plan: "solo",
        expires: null,
        validated_at: "not-a-number",
      })
    );

    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: async () => ({ valid: true, plan: "solo", expires: null }),
    } as Response);

    const result = await validateLicense("test-key");
    expect(globalThis.fetch).toHaveBeenCalledOnce(); // corrupted cache ignored → server hit
    expect(result!.valid).toBe(true);
  });
});

// ── getProLatestVersion ───────────────────────────────

describe("getProLatestVersion", () => {
  it("fetches version from server", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: async () => ({ version: "147.0.1234.5" }),
    } as Response);

    const version = await getProLatestVersion();
    expect(version).toBe("147.0.1234.5");
  });

  it("sends X-Platform header", async () => {
    vi.spyOn(config, "getPlatformTag").mockReturnValue("darwin-arm64");
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: async () => ({ version: "147.0.1234.5" }),
    } as Response);

    await getProLatestVersion();

    const init = fetchSpy.mock.calls[0]![1] as RequestInit;
    expect((init.headers as Record<string, string>)["X-Platform"]).toBe(
      "darwin-arm64",
    );
  });

  it("rate limited by marker file", async () => {
    vi.spyOn(config, "getPlatformTag").mockReturnValue("darwin-arm64");
    const marker = path.join(tmpDir, ".last_pro_version_check_darwin-arm64");
    fs.writeFileSync(marker, "147.0.1234.5");

    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const version = await getProLatestVersion();

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(version).toBe("147.0.1234.5");
  });

  it("network error returns null", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("network"));
    const version = await getProLatestVersion();
    expect(version).toBeNull();
  });
});

// ── Config pro parameter ──────────────────────────────

describe("config pro parameter", () => {
  it("getBinaryDir adds -pro suffix", () => {
    const normal = config.getBinaryDir("147.0.0.0");
    const pro = config.getBinaryDir("147.0.0.0", true);
    expect(normal).toMatch(/chromium-147\.0\.0\.0$/);
    expect(pro).toMatch(/chromium-147\.0\.0\.0-pro$/);
  });

  it("getBinaryDir default has no suffix", () => {
    const normal = config.getBinaryDir("147.0.0.0");
    expect(normal).not.toMatch(/-pro$/);
  });
});
