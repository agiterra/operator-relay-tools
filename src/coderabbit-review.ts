import { Database } from "bun:sqlite";
import { createHash } from "node:crypto";
import {
  appendFileSync,
  chmodSync,
  closeSync,
  existsSync,
  lstatSync,
  mkdirSync,
  openSync,
} from "node:fs";
import { dirname } from "node:path";
import type { GithubTokenSource } from "./github-token-source.js";

export const CODERABBIT_FULL_REVIEW_COMMENT = "@coderabbitai full review";
export const CODERABBIT_REVIEW_METHOD = "github.coderabbit_full_review";
export const EXPECTED_GITHUB_LOGIN = "mividtim";

const GITHUB_API = "https://api.github.com";
const SHA_RE = /^[0-9a-f]{40}$/;
const REPO_RE = /^fabrica-land\/[a-z0-9][a-z0-9._-]{0,99}$/;
// Same shape as github-comment-capabilities' IDEMPOTENCY_RE — the 2026-07-27
// idempotency-key rollout added the key to the MCP schema and the comment
// handlers but NOT here, so clients following the advertised schema were
// REFUSED by this handler alone ('unexpected request property') and every CR
// kick on 08-07 died at the broker while reading as "CR stalled".
const IDEMPOTENCY_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$/;
const REQUEST_KEYS = new Set([
  "repo",
  "pr_number",
  "review_mode",
  "expected_head_sha",
  "dry_run",
  "client_idempotency_key",
]);

export type CoderabbitReviewRequest = {
  repo: string;
  pr_number: number;
  review_mode: "full";
  expected_head_sha: string;
  dry_run?: boolean;
  client_idempotency_key?: string;
};

export type VerifiedCaller = {
  source: string;
  sourcePubkey?: string | null;
};

export type ReviewBrokerResult = {
  request_id: string;
  repo: string;
  pr_number: number;
  head_sha: string;
  review_mode: "full";
  dry_run: boolean;
  would_post?: boolean;
  posted?: boolean;
  idempotent?: boolean;
  comment_id?: number;
  comment_url?: string;
  github_login: string;
};

type Fetch = typeof globalThis.fetch;

export type ReviewBrokerConfig = {
  allowedRepos: ReadonlySet<string>;
  allowedCallers: ReadonlyMap<string, ReadonlySet<string>>;
  tokenSource: GithubTokenSource;
  stateFile: string;
  auditFile: string;
  minimumIntervalMs?: number;
  fetchImpl?: Fetch;
  now?: () => number;
};

type GithubPr = {
  number?: number;
  state?: string;
  head?: { sha?: string };
  base?: { repo?: { full_name?: string } };
};

type GithubComment = {
  id?: number;
  body?: string;
  html_url?: string;
  user?: { login?: string };
};

type StoredRequest = {
  status: string;
  comment_id: number | null;
  comment_url: string | null;
  requested_at: number;
};

type ReservationDecision =
  | { kind: "reserved"; key: string }
  | { kind: "idempotent"; key: string; previous: StoredRequest };

function ensurePrivateParent(path: string): void {
  const parent = dirname(path);
  mkdirSync(parent, { recursive: true, mode: 0o700 });
  const directory = lstatSync(parent);
  const uid = typeof process.getuid === "function" ? process.getuid() : directory.uid;
  if (directory.isSymbolicLink() || !directory.isDirectory()) {
    throw new Error("broker data parent must be a regular directory");
  }
  if (directory.uid !== uid || (directory.mode & 0o077) !== 0) {
    throw new Error("broker data parent must be runtime-owned and private (0700)");
  }
}

function assertOwnerOnlyFile(path: string, label: string): void {
  const link = lstatSync(path);
  if (link.isSymbolicLink()) throw new Error(`${label} must not be a symlink`);
  if (!link.isFile()) throw new Error(`${label} must be a regular file`);
  const uid = typeof process.getuid === "function" ? process.getuid() : link.uid;
  if (link.uid !== uid) throw new Error(`${label} must be owned by the broker runtime uid`);
  if ((link.mode & 0o077) !== 0) throw new Error(`${label} permissions must be owner-only (0600)`);
}

function createPrivateFile(path: string): void {
  ensurePrivateParent(path);
  const fd = openSync(path, "a", 0o600);
  closeSync(fd);
  chmodSync(path, 0o600);
}

function parseRequest(input: unknown): CoderabbitReviewRequest {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("request must be an object");
  }
  const raw = input as Record<string, unknown>;
  for (const key of Object.keys(raw)) {
    if (!REQUEST_KEYS.has(key)) throw new Error(`unexpected request property '${key}'`);
  }
  if (typeof raw.repo !== "string") throw new Error("repo must be a string");
  if (!Number.isSafeInteger(raw.pr_number) || (raw.pr_number as number) < 1) {
    throw new Error("pr_number must be a positive integer");
  }
  if (raw.review_mode !== "full") throw new Error("review_mode must be exactly 'full'");
  if (typeof raw.expected_head_sha !== "string" || !SHA_RE.test(raw.expected_head_sha)) {
    throw new Error("expected_head_sha must be a lowercase 40-character commit SHA");
  }
  if (raw.dry_run !== undefined && typeof raw.dry_run !== "boolean") {
    throw new Error("dry_run must be a boolean");
  }
  if (
    raw.client_idempotency_key !== undefined &&
    (typeof raw.client_idempotency_key !== "string" || !IDEMPOTENCY_RE.test(raw.client_idempotency_key))
  ) {
    throw new Error("client_idempotency_key must be 16-128 safe ASCII characters");
  }
  return {
    repo: raw.repo,
    pr_number: raw.pr_number as number,
    review_mode: "full",
    expected_head_sha: raw.expected_head_sha,
    dry_run: raw.dry_run as boolean | undefined,
    client_idempotency_key: raw.client_idempotency_key as string | undefined,
  };
}

function requestKey(req: CoderabbitReviewRequest): string {
  // Include the exact comment text in the key: a template change (e.g. the
  // "@coderabbitai review" → "@coderabbitai full review" fix) MUST bust dedupe,
  // otherwise a corrected command is silently masked by an old (pr, head) record.
  // 2026-09-01 (Brioche, api #1827): the client key was validated but never keyed, so once a
  // (pr, head) request was 'posted' nothing could re-trigger CodeRabbit on an unchanged head —
  // even after CodeRabbit itself answered "Review rate limited" and reviewed nothing. A caller
  // that supplies a FRESH client_idempotency_key now gets a fresh request (still subject to
  // the per-PR minimum interval); the SAME key stays idempotent; omitting it keeps the old
  // (repo, pr, head, mode, comment) dedupe unchanged.
  return createHash("sha256")
    .update(
      `${req.repo}\0${req.pr_number}\0${req.expected_head_sha}\0${req.review_mode}\0${CODERABBIT_FULL_REVIEW_COMMENT}\0${req.client_idempotency_key ?? ""}`,
    )
    .digest("hex");
}

function safeAuditError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return message.slice(0, 500);
}

export class CoderabbitReviewBroker {
  private readonly db: Database;
  private readonly fetchImpl: Fetch;
  private readonly now: () => number;
  private readonly minimumIntervalMs: number;
  private readonly expectedGithubLogin: string;

  constructor(private readonly config: ReviewBrokerConfig) {
    if (config.allowedRepos.size === 0) throw new Error("at least one repository must be allowlisted");
    if (config.allowedCallers.size === 0) throw new Error("at least one caller must be allowlisted");
    for (const repo of config.allowedRepos) this.validateRepo(repo);
    for (const [source, keys] of config.allowedCallers) {
      if (!/^[A-Za-z0-9][A-Za-z0-9@._-]{0,127}$/.test(source) || keys.size === 0) {
        throw new Error("every caller needs a canonical id and at least one public key");
      }
      for (const key of keys) {
        if (key.length < 16 || key.length > 256 || !/^[A-Za-z0-9+/_=-]+$/.test(key)) {
          throw new Error(`caller '${source}' contains an invalid public key`);
        }
      }
    }

    this.fetchImpl = config.fetchImpl ?? fetch;
    this.now = config.now ?? Date.now;
    this.minimumIntervalMs = config.minimumIntervalMs ?? 30 * 60_000;
    this.expectedGithubLogin = EXPECTED_GITHUB_LOGIN;
    if (!Number.isSafeInteger(this.minimumIntervalMs) || this.minimumIntervalMs < 1) {
      throw new Error("minimumIntervalMs must be a positive safe integer");
    }

    if (!existsSync(config.auditFile)) createPrivateFile(config.auditFile);
    assertOwnerOnlyFile(config.auditFile, "audit file");

    const stateExisted = existsSync(config.stateFile);
    ensurePrivateParent(config.stateFile);
    this.db = new Database(config.stateFile, { create: true });
    if (!stateExisted) chmodSync(config.stateFile, 0o600);
    assertOwnerOnlyFile(config.stateFile, "state database");
    this.db.exec("PRAGMA journal_mode=WAL");
    for (const sidecar of [`${config.stateFile}-wal`, `${config.stateFile}-shm`]) {
      if (existsSync(sidecar)) {
        chmodSync(sidecar, 0o600);
        assertOwnerOnlyFile(sidecar, "state database sidecar");
      }
    }
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS review_requests (
        request_key TEXT PRIMARY KEY,
        repo TEXT NOT NULL,
        pr_number INTEGER NOT NULL,
        head_sha TEXT NOT NULL,
        review_mode TEXT NOT NULL,
        caller TEXT NOT NULL,
        status TEXT NOT NULL,
        requested_at INTEGER NOT NULL,
        posted_at INTEGER,
        comment_id INTEGER,
        comment_url TEXT,
        error TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_review_requests_target
      ON review_requests(repo, pr_number, posted_at);
    `);
  }

  close(): void {
    this.db.close();
  }

  isCallerAllowed(caller: VerifiedCaller): boolean {
    const keys = this.config.allowedCallers.get(caller.source);
    return Boolean(caller.sourcePubkey && keys?.has(caller.sourcePubkey));
  }

  private validateRepo(repo: string): void {
    if (repo !== repo.normalize("NFKC")) throw new Error("repo must use canonical Unicode form");
    if (!REPO_RE.test(repo)) throw new Error("repo must be a canonical fabrica-land owner/repository name");
    const name = repo.split("/")[1]!;
    if (name === "." || name === ".." || name.includes("..")) {
      throw new Error("repo contains a forbidden path segment");
    }
  }

  private assertTargetAllowed(req: CoderabbitReviewRequest): void {
    this.validateRepo(req.repo);
    if (!this.config.allowedRepos.has(req.repo)) throw new Error(`repository '${req.repo}' is not allowlisted`);
  }

  private audit(event: Record<string, unknown>): void {
    assertOwnerOnlyFile(this.config.auditFile, "audit file");
    appendFileSync(
      this.config.auditFile,
      `${JSON.stringify({ at: new Date(this.now()).toISOString(), ...event })}\n`,
      { encoding: "utf8", mode: 0o600 },
    );
  }

  private async githubJson<T>(token: string, path: string, init: RequestInit = {}): Promise<T> {
    if (!path.startsWith("/")) throw new Error("internal GitHub path must be relative");
    const headers = new Headers(init.headers);
    // Security headers are set after caller-provided initialization so even an
    // internal refactor cannot override broker identity or content negotiation.
    headers.set("Authorization", `Bearer ${token}`);
    headers.set("Accept", "application/vnd.github+json");
    headers.set("Content-Type", "application/json");
    headers.set("User-Agent", "agiterra-coderabbit-review-broker");
    headers.set("X-GitHub-Api-Version", "2022-11-28");
    const response = await this.fetchImpl(`${GITHUB_API}${path}`, {
      ...init,
      headers,
      redirect: "error",
    });
    if (!response.ok) throw new Error(`GitHub API request failed (${response.status})`);
    return (await response.json()) as T;
  }

  private githubPath(repo: string, suffix: string): string {
    const [owner, name] = repo.split("/");
    return `/repos/${encodeURIComponent(owner!)}/${encodeURIComponent(name!)}${suffix}`;
  }

  private async validateIdentityAndPr(token: string, req: CoderabbitReviewRequest): Promise<GithubPr> {
    const user = await this.githubJson<{ login?: string }>(token, "/user");
    if (user.login !== this.expectedGithubLogin) {
      throw new Error("broker GitHub credential identity drifted from the required operator login");
    }
    const pr = await this.githubJson<GithubPr>(token, this.githubPath(req.repo, `/pulls/${req.pr_number}`));
    if (pr.number !== req.pr_number || pr.base?.repo?.full_name !== req.repo) {
      throw new Error("GitHub target identity drifted from the requested repository/PR");
    }
    if (pr.state !== "open") throw new Error("target PR is not open");
    if (pr.head?.sha !== req.expected_head_sha) throw new Error("target PR head drifted from expected_head_sha");
    return pr;
  }

  private stored(key: string): StoredRequest | null {
    return this.db
      .query<StoredRequest, [string]>(
        "SELECT status, comment_id, comment_url, requested_at FROM review_requests WHERE request_key = ?",
      )
      .get(key) ?? null;
  }

  private latestPostedAt(repo: string, pr: number): number | null {
    const row = this.db
      .query<{ posted_at: number | null }, [string, number]>(
        "SELECT MAX(posted_at) AS posted_at FROM review_requests WHERE repo = ? AND pr_number = ? AND status = 'posted'",
      )
      .get(repo, pr);
    return row?.posted_at ?? null;
  }

  private decideAndReserve(
    req: CoderabbitReviewRequest,
    caller: string,
    now: number,
  ): ReservationDecision {
    const key = requestKey(req);
    const transaction = this.db.transaction(() => {
      const existing = this.stored(key);
      if (existing?.status === "posted") {
        return { kind: "idempotent", key, previous: existing } as const;
      }
      if (existing?.status === "unsafe_posted" || existing?.status === "processing") {
        throw new Error(
          "an identical review request is in progress or has an ambiguous prior outcome; operator review is required",
        );
      }

      const ambiguous = this.db
        .query<{ status: string }, [string, number]>(
          `SELECT status FROM review_requests
           WHERE repo = ? AND pr_number = ? AND status IN ('processing', 'unsafe_posted')
           LIMIT 1`,
        )
        .get(req.repo, req.pr_number);
      if (ambiguous) {
        throw new Error(
          "this PR has an in-progress or ambiguous prior request; operator review is required",
        );
      }

      const postedAt = this.latestPostedAt(req.repo, req.pr_number);
      if (postedAt !== null && now - postedAt < this.minimumIntervalMs) {
        throw new Error("review request is rate-limited for this PR");
      }

      if (existing && existing.status !== "failed") {
        throw new Error(`stored review request has unsupported state '${existing.status}'`);
      }
      if (existing) {
        const update = this.db
          .query(
            `UPDATE review_requests SET
               caller = ?, status = 'processing', requested_at = ?, posted_at = NULL,
               comment_id = NULL, comment_url = NULL, error = NULL
             WHERE request_key = ? AND status = 'failed'`,
          )
          .run(caller, now, key);
        if (update.changes !== 1) throw new Error("failed request reservation lost an atomic race");
      } else {
        this.db
          .query(
            `INSERT INTO review_requests
             (request_key, repo, pr_number, head_sha, review_mode, caller, status, requested_at)
             VALUES (?, ?, ?, ?, ?, ?, 'processing', ?)`,
          )
          .run(key, req.repo, req.pr_number, req.expected_head_sha, req.review_mode, caller, now);
      }
      return { kind: "reserved", key } as const;
    });
    return transaction.immediate();
  }

  private markFailed(key: string, error: unknown): void {
    this.db.query(
      "UPDATE review_requests SET status = 'failed', error = ? WHERE request_key = ? AND status = 'processing'",
    )
      .run(safeAuditError(error), key);
  }

  private markUnsafePosted(key: string, comment: GithubComment, error: unknown): void {
    this.db
      .query(
        "UPDATE review_requests SET status = 'unsafe_posted', posted_at = ?, comment_id = ?, comment_url = ?, error = ? WHERE request_key = ? AND status = 'processing'",
      )
      .run(this.now(), comment.id ?? null, comment.html_url ?? null, safeAuditError(error), key);
  }

  private markPosted(key: string, comment: GithubComment): void {
    const update = this.db
      .query(
        "UPDATE review_requests SET status = 'posted', posted_at = ?, comment_id = ?, comment_url = ?, error = NULL WHERE request_key = ? AND status = 'processing'",
      )
      .run(this.now(), comment.id!, comment.html_url ?? null, key);
    if (update.changes !== 1) {
      throw new Error("posted review request could not commit its terminal state");
    }
  }

  async request(input: unknown, caller: VerifiedCaller): Promise<ReviewBrokerResult> {
    const requestId = crypto.randomUUID();
    const raw = input && typeof input === "object" ? (input as Record<string, unknown>) : {};
    this.audit({
      event: "request",
      request_id: requestId,
      caller: caller.source,
      verified_key_present: Boolean(caller.sourcePubkey),
      repo: typeof raw.repo === "string" ? raw.repo : null,
      pr_number: typeof raw.pr_number === "number" ? raw.pr_number : null,
      dry_run: raw.dry_run === true,
    });

    let key: string | null = null;
    let reserved = false;
    let postAttempted = false;
    try {
      if (!this.isCallerAllowed(caller)) throw new Error("caller identity/public key is not authorized");
      const req = parseRequest(input);
      this.assertTargetAllowed(req);

      if (req.dry_run) {
        const token = await this.config.tokenSource.getToken();
        await this.validateIdentityAndPr(token, req);
        const result: ReviewBrokerResult = {
          request_id: requestId,
          repo: req.repo,
          pr_number: req.pr_number,
          head_sha: req.expected_head_sha,
          review_mode: "full",
          dry_run: true,
          would_post: true,
          github_login: this.expectedGithubLogin,
        };
        this.audit({ event: "result", caller: caller.source, outcome: "dry_run", ...result });
        return result;
      }

      const decision = this.decideAndReserve(req, caller.source, this.now());
      key = decision.key;
      if (decision.kind === "idempotent") {
        const result: ReviewBrokerResult = {
          request_id: requestId,
          repo: req.repo,
          pr_number: req.pr_number,
          head_sha: req.expected_head_sha,
          review_mode: "full",
          dry_run: false,
          posted: true,
          idempotent: true,
          comment_id: decision.previous.comment_id ?? undefined,
          comment_url: decision.previous.comment_url ?? undefined,
          github_login: this.expectedGithubLogin,
        };
        this.audit({ event: "result", caller: caller.source, outcome: "idempotent", ...result });
        return result;
      }
      reserved = true;

      const token = await this.config.tokenSource.getToken();
      // Validate identity and target immediately before the irreversible write.
      await this.validateIdentityAndPr(token, req);
      postAttempted = true;
      const created = await this.githubJson<GithubComment>(
        token,
        this.githubPath(req.repo, `/issues/${req.pr_number}/comments`),
        { method: "POST", body: JSON.stringify({ body: CODERABBIT_FULL_REVIEW_COMMENT }) },
      );
      if (!Number.isSafeInteger(created.id)) {
        const error = new Error("GitHub comment creation response did not contain a valid comment id");
        this.markUnsafePosted(key, created, error);
        throw error;
      }

      const readback = await this.githubJson<GithubComment>(
        token,
        this.githubPath(req.repo, `/issues/comments/${created.id}`),
      );
      const finalPr = await this.githubJson<GithubPr>(
        token,
        this.githubPath(req.repo, `/pulls/${req.pr_number}`),
      );
      if (
        readback.id !== created.id ||
        readback.body !== CODERABBIT_FULL_REVIEW_COMMENT ||
        readback.user?.login !== this.expectedGithubLogin
      ) {
        const error = new Error("GitHub comment readback identity/body mismatch");
        this.markUnsafePosted(key, readback.id ? readback : created, error);
        throw error;
      }
      if (finalPr.head?.sha !== req.expected_head_sha || finalPr.state !== "open") {
        const error = new Error("target PR drifted during comment publication");
        this.markUnsafePosted(key, readback, error);
        throw error;
      }

      this.markPosted(key, readback);
      const result: ReviewBrokerResult = {
        request_id: requestId,
        repo: req.repo,
        pr_number: req.pr_number,
        head_sha: req.expected_head_sha,
        review_mode: "full",
        dry_run: false,
        posted: true,
        idempotent: false,
        comment_id: readback.id,
        comment_url: readback.html_url,
        github_login: this.expectedGithubLogin,
      };
      this.audit({ event: "result", caller: caller.source, outcome: "posted", ...result });
      return result;
    } catch (error) {
      if (reserved && key) {
        const current = this.stored(key);
        if (current?.status === "processing") {
          if (postAttempted) this.markUnsafePosted(key, {}, error);
          else this.markFailed(key, error);
        }
      }
      this.audit({
        event: "result",
        request_id: requestId,
        caller: caller.source,
        outcome: "refused_or_failed",
        error: safeAuditError(error),
      });
      throw error;
    }
  }
}

export function parseAllowedRepos(value: string): ReadonlySet<string> {
  return new Set(value.split(",").map((item) => item.trim()).filter(Boolean));
}

export function parseAllowedCallers(value: string): ReadonlyMap<string, ReadonlySet<string>> {
  const raw = JSON.parse(value) as Record<string, unknown>;
  const result = new Map<string, ReadonlySet<string>>();
  for (const [source, keys] of Object.entries(raw)) {
    if (!Array.isArray(keys) || keys.some((key) => typeof key !== "string" || key.length < 16)) {
      throw new Error(`caller '${source}' must map to an array of public keys`);
    }
    result.set(source, new Set(keys));
  }
  return result;
}
