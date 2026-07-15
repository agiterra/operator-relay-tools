import {
  chmodSync,
  closeSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";

const GITHUB_OAUTH_TOKEN_URL = "https://github.com/login/oauth/access_token";
const GITHUB_API = "https://api.github.com";
const SECRET_MAX_BYTES = 16 * 1024;
type Fetch = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

export interface GithubTokenSource {
  readonly kind: "github_app_user" | "fine_grained_pat";
  getToken(): Promise<string>;
}

type GithubAppUserTokenState = {
  version: 1;
  access_token: string;
  expires_at: number;
  refresh_token: string;
  refresh_token_expires_at: number;
  token_type?: string;
  scope?: string;
};

type GithubRefreshResponse = {
  access_token?: unknown;
  expires_in?: unknown;
  refresh_token?: unknown;
  refresh_token_expires_in?: unknown;
  token_type?: unknown;
  scope?: unknown;
};

export type GithubAppUserTokenSourceConfig = {
  clientId: string;
  clientSecretFile: string;
  tokenStateFile: string;
  refreshMarginMs?: number;
  fetchImpl?: Fetch;
  now?: () => number;
};

function runtimeUid(fallback: number): number {
  return typeof process.getuid === "function" ? process.getuid() : fallback;
}

function assertPrivateDirectory(path: string, label: string): void {
  const entry = lstatSync(path);
  if (entry.isSymbolicLink() || !entry.isDirectory()) {
    throw new Error(`${label} must be a regular directory`);
  }
  if (entry.uid !== runtimeUid(entry.uid) || (entry.mode & 0o077) !== 0) {
    throw new Error(`${label} must be runtime-owned and private (0700)`);
  }
}

function ensurePrivateParent(path: string): void {
  const parent = dirname(path);
  mkdirSync(parent, { recursive: true, mode: 0o700 });
  assertPrivateDirectory(parent, "credential parent");
}

function assertPrivateFile(path: string, label: string): void {
  ensurePrivateParent(path);
  const entry = lstatSync(path);
  if (entry.isSymbolicLink() || !entry.isFile()) throw new Error(`${label} must be a regular file`);
  if (entry.uid !== runtimeUid(entry.uid) || (entry.mode & 0o077) !== 0) {
    throw new Error(`${label} must be runtime-owned and private (0600)`);
  }
  const stat = statSync(path);
  if (stat.size < 1 || stat.size > SECRET_MAX_BYTES) throw new Error(`${label} has an invalid size`);
}

function validateSecret(value: unknown, label: string): string {
  if (typeof value !== "string" || !value || value.length > SECRET_MAX_BYTES || /\s/.test(value)) {
    throw new Error(`${label} is empty or malformed`);
  }
  return value;
}

function validatePrefixedSecret(value: unknown, prefix: string, label: string): string {
  const secret = validateSecret(value, label);
  if (!secret.startsWith(prefix)) throw new Error(`${label} has an unexpected credential type`);
  return secret;
}

function readSecret(path: string, label: string): string {
  assertPrivateFile(path, label);
  return validateSecret(readFileSync(path, "utf8").trim(), label);
}

function positiveSafeInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) {
    throw new Error(`${label} must be a positive safe integer`);
  }
  return value as number;
}

function checkedNow(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1) throw new Error("runtime clock is invalid");
  return value;
}

function expiryFromLifetime(now: number, lifetimeSeconds: unknown, label: string): number {
  const seconds = positiveSafeInteger(lifetimeSeconds, label);
  const milliseconds = seconds * 1000;
  const expiry = now + milliseconds;
  if (!Number.isSafeInteger(milliseconds) || !Number.isSafeInteger(expiry)) {
    throw new Error(`${label} exceeds the supported time range`);
  }
  return expiry;
}

function readTokenState(path: string): GithubAppUserTokenState {
  assertPrivateFile(path, "GitHub App user-token state");
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw new Error("GitHub App user-token state is not valid JSON");
  }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("GitHub App user-token state must be an object");
  }
  const state = raw as Record<string, unknown>;
  if (state.version !== 1) throw new Error("GitHub App user-token state version is unsupported");
  return {
    version: 1,
    access_token: validatePrefixedSecret(
      state.access_token,
      "ghu_",
      "GitHub App user access token",
    ),
    expires_at: positiveSafeInteger(state.expires_at, "access-token expiry"),
    refresh_token: validatePrefixedSecret(
      state.refresh_token,
      "ghr_",
      "GitHub App user refresh token",
    ),
    refresh_token_expires_at: positiveSafeInteger(
      state.refresh_token_expires_at,
      "refresh-token expiry",
    ),
    token_type: typeof state.token_type === "string" ? state.token_type.slice(0, 64) : undefined,
    scope: typeof state.scope === "string" ? state.scope.slice(0, 1024) : undefined,
  };
}

function atomicWritePrivateState(path: string, state: GithubAppUserTokenState): void {
  ensurePrivateParent(path);
  const temporary = join(dirname(path), `.github-user-token.${process.pid}.${crypto.randomUUID()}.tmp`);
  let fd: number | null = null;
  try {
    fd = openSync(temporary, "wx", 0o600);
    writeFileSync(fd, `${JSON.stringify(state)}\n`, "utf8");
    fsyncSync(fd);
    closeSync(fd);
    fd = null;
    chmodSync(temporary, 0o600);
    renameSync(temporary, path);
    assertPrivateFile(path, "GitHub App user-token state");
  } catch (error) {
    if (fd !== null) closeSync(fd);
    rmSync(temporary, { force: true });
    throw error;
  }
}

export class FineGrainedPatFileTokenSource implements GithubTokenSource {
  readonly kind = "fine_grained_pat" as const;

  constructor(private readonly tokenFile: string) {}

  async getToken(): Promise<string> {
    return validatePrefixedSecret(
      readSecret(this.tokenFile, "fine-grained GitHub credential file"),
      "github_pat_",
      "fine-grained GitHub credential",
    );
  }
}

export class GithubAppUserTokenSource implements GithubTokenSource {
  readonly kind = "github_app_user" as const;
  private readonly fetchImpl: Fetch;
  private readonly now: () => number;
  private readonly refreshMarginMs: number;
  private refreshInFlight: Promise<string> | null = null;

  constructor(private readonly config: GithubAppUserTokenSourceConfig) {
    if (!/^[A-Za-z0-9._-]{6,255}$/.test(config.clientId)) {
      throw new Error("GitHub App client ID is malformed");
    }
    this.fetchImpl = config.fetchImpl ?? fetch;
    this.now = config.now ?? Date.now;
    this.refreshMarginMs = config.refreshMarginMs ?? 10 * 60_000;
    if (!Number.isSafeInteger(this.refreshMarginMs) || this.refreshMarginMs < 60_000) {
      throw new Error("refreshMarginMs must be a safe integer of at least 60000");
    }
  }

  async getToken(): Promise<string> {
    const state = readTokenState(this.config.tokenStateFile);
    const now = checkedNow(this.now());
    if (state.refresh_token_expires_at <= now) {
      throw new Error("GitHub App user refresh token is expired; owner reauthorization is required");
    }
    if (state.expires_at - now > this.refreshMarginMs) return state.access_token;
    if (this.refreshInFlight) return this.refreshInFlight;
    const refresh = this.refresh(state).finally(() => {
      if (this.refreshInFlight === refresh) this.refreshInFlight = null;
    });
    this.refreshInFlight = refresh;
    return refresh;
  }

  private async refresh(state: GithubAppUserTokenState): Promise<string> {
    const clientSecret = readSecret(this.config.clientSecretFile, "GitHub App client-secret file");
    const body = new URLSearchParams({
      client_id: this.config.clientId,
      client_secret: clientSecret,
      grant_type: "refresh_token",
      refresh_token: state.refresh_token,
    });
    const response = await this.fetchImpl(GITHUB_OAUTH_TOKEN_URL, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "agiterra-coderabbit-review-broker",
      },
      body: body.toString(),
      redirect: "error",
    });
    if (!response.ok) {
      throw new Error(`GitHub App user-token refresh failed (${response.status})`);
    }
    const payload = (await response.json()) as GithubRefreshResponse;
    const now = checkedNow(this.now());
    const refreshed: GithubAppUserTokenState = {
      version: 1,
      access_token: validatePrefixedSecret(
        payload.access_token,
        "ghu_",
        "refreshed GitHub App user access token",
      ),
      expires_at: expiryFromLifetime(now, payload.expires_in, "access-token lifetime"),
      refresh_token: validatePrefixedSecret(
        payload.refresh_token,
        "ghr_",
        "refreshed GitHub App user refresh token",
      ),
      refresh_token_expires_at: expiryFromLifetime(
        now,
        payload.refresh_token_expires_in,
        "refresh-token lifetime",
      ),
      token_type: typeof payload.token_type === "string" ? payload.token_type.slice(0, 64) : undefined,
      scope: typeof payload.scope === "string" ? payload.scope.slice(0, 1024) : undefined,
    };
    atomicWritePrivateState(this.config.tokenStateFile, refreshed);
    return refreshed.access_token;
  }

  /**
   * Owner-runtime emergency action. This is deliberately not part of the
   * GithubTokenSource interface and is never registered as an agent MCP tool.
   * Deleting the grant revokes every access/refresh token for this app/user.
   */
  async revokeAuthorization(): Promise<void> {
    if (this.refreshInFlight) {
      throw new Error("cannot revoke while a token refresh is in progress");
    }
    const state = readTokenState(this.config.tokenStateFile);
    const clientSecret = readSecret(this.config.clientSecretFile, "GitHub App client-secret file");
    const basic = Buffer.from(`${this.config.clientId}:${clientSecret}`, "utf8").toString("base64");
    const response = await this.fetchImpl(
      `${GITHUB_API}/applications/${encodeURIComponent(this.config.clientId)}/grant`,
      {
        method: "DELETE",
        headers: {
          Accept: "application/vnd.github+json",
          Authorization: `Basic ${basic}`,
          "Content-Type": "application/json",
          "User-Agent": "agiterra-coderabbit-review-broker",
          "X-GitHub-Api-Version": "2022-11-28",
        },
        body: JSON.stringify({ access_token: state.access_token }),
        redirect: "error",
      },
    );
    if (response.status !== 204) {
      throw new Error(`GitHub App authorization revocation failed (${response.status})`);
    }
    rmSync(this.config.tokenStateFile, { force: true });
  }
}

export function githubTokenSourceFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): GithubTokenSource {
  const source = env.CODERABBIT_BROKER_TOKEN_SOURCE?.trim();
  if (source === "github_app_user") {
    return new GithubAppUserTokenSource({
      clientId: requiredEnv(env, "CODERABBIT_BROKER_GITHUB_APP_CLIENT_ID"),
      clientSecretFile: requiredEnv(env, "CODERABBIT_BROKER_GITHUB_APP_CLIENT_SECRET_FILE"),
      tokenStateFile: requiredEnv(env, "CODERABBIT_BROKER_GITHUB_APP_USER_TOKEN_STATE_FILE"),
      refreshMarginMs: env.CODERABBIT_BROKER_GITHUB_APP_REFRESH_MARGIN_MS
        ? Number(env.CODERABBIT_BROKER_GITHUB_APP_REFRESH_MARGIN_MS)
        : undefined,
    });
  }
  if (source === "fine_grained_pat") {
    return new FineGrainedPatFileTokenSource(requiredEnv(env, "CODERABBIT_BROKER_TOKEN_FILE"));
  }
  throw new Error(
    "CODERABBIT_BROKER_TOKEN_SOURCE must explicitly be 'github_app_user' or 'fine_grained_pat'",
  );
}

function requiredEnv(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}
