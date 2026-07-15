import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  FineGrainedPatFileTokenSource,
  GithubAppUserTokenSource,
  githubTokenSourceFromEnv,
} from "./github-token-source.js";

const NOW = 1_700_000_000_000;
let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "github-token-source-"));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function privateFile(name: string, contents: string): string {
  const path = join(dir, name);
  writeFileSync(path, contents, { mode: 0o600 });
  chmodSync(path, 0o600);
  return path;
}

function stateFile(overrides: Record<string, unknown> = {}): string {
  return privateFile(
    "user-token.json",
    `${JSON.stringify({
      version: 1,
      access_token: "ghu_old-access-token",
      expires_at: NOW + 60 * 60_000,
      refresh_token: "ghr_old-refresh-token",
      refresh_token_expires_at: NOW + 30 * 24 * 60 * 60_000,
      token_type: "bearer",
      scope: "",
      ...overrides,
    })}\n`,
  );
}

describe("GitHub token sources", () => {
  test("fine-grained PAT source reads owner-only file on every request", async () => {
    const path = privateFile("pat", "github_pat_first-token\n");
    const source = new FineGrainedPatFileTokenSource(path);
    expect(await source.getToken()).toBe("github_pat_first-token");
    writeFileSync(path, "github_pat_rotated-token\n", { mode: 0o600 });
    chmodSync(path, 0o600);
    expect(await source.getToken()).toBe("github_pat_rotated-token");
  });

  test("fine-grained PAT fallback rejects other credential types", async () => {
    const source = new FineGrainedPatFileTokenSource(privateFile("pat", "ghu_wrong-token-type\n"));
    await expect(source.getToken()).rejects.toThrow(/unexpected credential type/);
  });

  test("GitHub App source returns a fresh user token without a refresh call", async () => {
    let calls = 0;
    const source = new GithubAppUserTokenSource({
      clientId: "Iv1.valid-client",
      clientSecretFile: privateFile("client-secret", "client-secret-value\n"),
      tokenStateFile: stateFile(),
      now: () => NOW,
      fetchImpl: (async () => {
        calls += 1;
        return new Response("unexpected", { status: 500 });
      }),
    });
    expect(await source.getToken()).toBe("ghu_old-access-token");
    expect(calls).toBe(0);
  });

  test("refreshes and atomically rotates expiring GitHub App user credentials once", async () => {
    const requests: Array<{ url: string; body: URLSearchParams; authorization: string | null }> = [];
    const state = stateFile({ expires_at: NOW + 1_000 });
    const source = new GithubAppUserTokenSource({
      clientId: "Iv1.valid-client",
      clientSecretFile: privateFile("client-secret", "client-secret-value\n"),
      tokenStateFile: state,
      now: () => NOW,
      fetchImpl: (async (input, init) => {
        const headers = new Headers(init?.headers);
        requests.push({
          url: String(input),
          body: new URLSearchParams(String(init?.body)),
          authorization: headers.get("authorization"),
        });
        return Response.json({
          access_token: "ghu_new-access-token",
          expires_in: 28_800,
          refresh_token: "ghr_new-refresh-token",
          refresh_token_expires_in: 15_552_000,
          token_type: "bearer",
          scope: "repo",
        });
      }),
    });

    const [first, second] = await Promise.all([source.getToken(), source.getToken()]);
    expect(first).toBe("ghu_new-access-token");
    expect(second).toBe("ghu_new-access-token");
    expect(requests).toHaveLength(1);
    expect(requests[0]!.url).toBe("https://github.com/login/oauth/access_token");
    expect(requests[0]!.authorization).toBeNull();
    expect(requests[0]!.body.get("grant_type")).toBe("refresh_token");
    expect(requests[0]!.body.get("client_id")).toBe("Iv1.valid-client");
    expect(requests[0]!.body.get("client_secret")).toBe("client-secret-value");
    expect(requests[0]!.body.get("refresh_token")).toBe("ghr_old-refresh-token");
    const persisted = JSON.parse(readFileSync(state, "utf8"));
    expect(persisted.access_token).toBe("ghu_new-access-token");
    expect(persisted.refresh_token).toBe("ghr_new-refresh-token");
    expect(statSync(state).mode & 0o077).toBe(0);
    expect(await source.getToken()).toBe("ghu_new-access-token");
    expect(requests).toHaveLength(1);
  });

  test("fails closed when the refresh token is expired", async () => {
    let called = false;
    const source = new GithubAppUserTokenSource({
      clientId: "Iv1.valid-client",
      clientSecretFile: privateFile("client-secret", "client-secret-value\n"),
      tokenStateFile: stateFile({
        expires_at: NOW - 1,
        refresh_token_expires_at: NOW - 1,
      }),
      now: () => NOW,
      fetchImpl: (async () => {
        called = true;
        return Response.json({});
      }),
    });
    await expect(source.getToken()).rejects.toThrow(/reauthorization/);
    expect(called).toBe(false);
  });

  test("does not expose an OAuth error response body", async () => {
    const source = new GithubAppUserTokenSource({
      clientId: "Iv1.valid-client",
      clientSecretFile: privateFile("client-secret", "client-secret-value\n"),
      tokenStateFile: stateFile({ expires_at: NOW - 1 }),
      now: () => NOW,
      fetchImpl: async () =>
        new Response('{"error":"bad_verification_code","secret":"do-not-log"}', { status: 401 }),
    });
    await expect(source.getToken()).rejects.toThrow("GitHub App user-token refresh failed (401)");
  });

  test("owner-only revocation deletes the app grant and local token state", async () => {
    const state = stateFile();
    const requests: Array<{ url: string; method: string; authorization: string; token: string }> = [];
    const source = new GithubAppUserTokenSource({
      clientId: "Iv1.valid-client",
      clientSecretFile: privateFile("client-secret", "client-secret-value\n"),
      tokenStateFile: state,
      now: () => NOW,
      fetchImpl: async (input, init) => {
        const body = JSON.parse(String(init?.body));
        requests.push({
          url: String(input),
          method: init?.method ?? "GET",
          authorization: new Headers(init?.headers).get("authorization") ?? "",
          token: body.access_token,
        });
        return new Response(null, { status: 204 });
      },
    });
    await source.revokeAuthorization();
    expect(requests).toHaveLength(1);
    expect(requests[0]!.url).toBe(
      "https://api.github.com/applications/Iv1.valid-client/grant",
    );
    expect(requests[0]!.method).toBe("DELETE");
    expect(Buffer.from(requests[0]!.authorization.slice("Basic ".length), "base64").toString()).toBe(
      "Iv1.valid-client:client-secret-value",
    );
    expect(requests[0]!.token).toBe("ghu_old-access-token");
    expect(existsSync(state)).toBe(false);
  });

  test("rejects group-readable token state and requires explicit source selection", async () => {
    const state = stateFile();
    chmodSync(state, 0o640);
    const source = new GithubAppUserTokenSource({
      clientId: "Iv1.valid-client",
      clientSecretFile: privateFile("client-secret", "client-secret-value\n"),
      tokenStateFile: state,
      now: () => NOW,
    });
    await expect(source.getToken()).rejects.toThrow(/owner-only|private/);
    expect(() => githubTokenSourceFromEnv({})).toThrow(/must explicitly/);
  });
});
