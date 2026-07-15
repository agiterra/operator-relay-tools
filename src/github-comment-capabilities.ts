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
import { EXPECTED_GITHUB_LOGIN, type VerifiedCaller } from "./coderabbit-review.js";

export const PR_COMMENT_METHOD = "github.pr_comment";
export const REVIEW_THREAD_REPLY_METHOD = "github.review_thread_reply";
export const COMMENT_CAPABILITIES = [PR_COMMENT_METHOD, REVIEW_THREAD_REPLY_METHOD] as const;

export type CommentCapability = (typeof COMMENT_CAPABILITIES)[number];
export type AuditTextPolicy = "hash" | "redacted_full";

export type CommentAuditMetadata = {
  tracking_ref: string;
  reason_code: "review_response" | "operator_request" | "incident_response" | "other";
};

type CommentRequestBase = {
  repo: string;
  pr_number: number;
  expected_head_sha: string;
  text: string;
  dry_run: boolean;
  client_idempotency_key: string;
  justification: string;
  audit_metadata: CommentAuditMetadata;
};

export type PrCommentRequest = CommentRequestBase;
export type ReviewThreadReplyRequest = CommentRequestBase & {
  review_comment_id: number;
};

export type GithubCommentCapabilityResult = {
  request_id: string;
  capability: CommentCapability;
  repo: string;
  pr_number: number;
  head_sha: string;
  review_comment_id?: number;
  text_sha256: string;
  dry_run: boolean;
  would_post?: boolean;
  posted?: boolean;
  idempotent?: boolean;
  comment_id?: number;
  comment_url?: string;
  github_login: string;
};

export type CapabilityCallerMap = ReadonlyMap<
  CommentCapability,
  ReadonlyMap<string, ReadonlySet<string>>
>;

export type GithubCommentCapabilitiesConfig = {
  allowedRepos: ReadonlySet<string>;
  allowedCapabilityCallers: CapabilityCallerMap;
  tokenSource: GithubTokenSource;
  stateFile: string;
  auditFile: string;
  auditTextPolicy?: AuditTextPolicy;
  prCommentMinimumIntervalMs?: number;
  reviewReplyMinimumIntervalMs?: number;
  fetchImpl?: typeof globalThis.fetch;
  now?: () => number;
};

type GithubPr = {
  number?: number;
  state?: string;
  head?: { sha?: string };
  base?: { repo?: { full_name?: string } };
};

type GithubIssueComment = {
  id?: number;
  body?: string;
  html_url?: string;
  user?: { login?: string };
};

type GithubReviewComment = GithubIssueComment & {
  pull_request_url?: string;
  commit_id?: string;
  position?: number | null;
  in_reply_to_id?: number;
};

type ParsedRequest = PrCommentRequest | ReviewThreadReplyRequest;

type StoredRequest = {
  status: string;
  payload_hash: string;
  comment_id: number | null;
  comment_url: string | null;
};

type ReservationDecision =
  | { kind: "reserved"; key: string }
  | { kind: "idempotent"; key: string; previous: StoredRequest };

const GITHUB_API = "https://api.github.com";
const SHA_RE = /^[0-9a-f]{40}$/;
const REPO_RE = /^fabrica-land\/[a-z0-9][a-z0-9._-]{0,99}$/;
const IDEMPOTENCY_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$/;
const TRACKING_RE = /^[A-Za-z0-9][A-Za-z0-9._:/#-]{0,127}$/;
const MAX_TEXT_BYTES = 8 * 1024;
const MAX_JUSTIFICATION_BYTES = 1024;
const BASE_KEYS = new Set([
  "repo",
  "pr_number",
  "expected_head_sha",
  "text",
  "dry_run",
  "client_idempotency_key",
  "justification",
  "audit_metadata",
]);
const AUDIT_METADATA_KEYS = new Set(["tracking_ref", "reason_code"]);
const REASON_CODES = new Set([
  "review_response",
  "operator_request",
  "incident_response",
  "other",
]);
const LIKELY_SECRET_PATTERNS = [
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/i,
  /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/i,
  /\bsk-[A-Za-z0-9_-]{20,}\b/i,
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/,
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/i,
  /\bBearer[ \t]+[A-Za-z0-9._~+/-]{20,}=*/i,
  /\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\b/,
  /-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----/i,
];

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
  const uid = typeof process.getuid === "function" ? process.getuid() : link.uid;
  if (link.isSymbolicLink() || !link.isFile()) throw new Error(`${label} must be a regular file`);
  if (link.uid !== uid || (link.mode & 0o077) !== 0) {
    throw new Error(`${label} must be runtime-owned and owner-only (0600)`);
  }
}

function createPrivateFile(path: string): void {
  ensurePrivateParent(path);
  const fd = openSync(path, "a", 0o600);
  closeSync(fd);
  chmodSync(path, 0o600);
}

function utf8Bytes(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function safeAuditError(error: unknown): string {
  return (error instanceof Error ? error.message : String(error)).slice(0, 500);
}

function assertSafeText(value: unknown): asserts value is string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error("text must be a nonempty string");
  }
  if (utf8Bytes(value) > MAX_TEXT_BYTES) throw new Error(`text exceeds ${MAX_TEXT_BYTES} UTF-8 bytes`);
  if (/\0|[\u0001-\u0008\u000B\u000C\u000E-\u001F\u007F]/u.test(value)) {
    throw new Error("text contains forbidden control characters");
  }
  if (LIKELY_SECRET_PATTERNS.some((pattern) => pattern.test(value))) {
    throw new Error("text appears to contain credential or private-key material");
  }
}

function parseAuditMetadata(value: unknown): CommentAuditMetadata {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("audit_metadata must be an object");
  }
  const raw = value as Record<string, unknown>;
  for (const key of Object.keys(raw)) {
    if (!AUDIT_METADATA_KEYS.has(key)) throw new Error(`unexpected audit_metadata property '${key}'`);
  }
  if (typeof raw.tracking_ref !== "string" || !TRACKING_RE.test(raw.tracking_ref)) {
    throw new Error("audit_metadata.tracking_ref is invalid");
  }
  if (typeof raw.reason_code !== "string" || !REASON_CODES.has(raw.reason_code)) {
    throw new Error("audit_metadata.reason_code is invalid");
  }
  return {
    tracking_ref: raw.tracking_ref,
    reason_code: raw.reason_code as CommentAuditMetadata["reason_code"],
  };
}

function parseRequest(capability: CommentCapability, input: unknown): ParsedRequest {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("request must be an object");
  }
  const raw = input as Record<string, unknown>;
  const allowed = new Set(BASE_KEYS);
  if (capability === REVIEW_THREAD_REPLY_METHOD) allowed.add("review_comment_id");
  for (const key of Object.keys(raw)) {
    if (!allowed.has(key)) throw new Error(`unexpected request property '${key}'`);
  }
  if (typeof raw.repo !== "string") throw new Error("repo must be a string");
  if (!Number.isSafeInteger(raw.pr_number) || (raw.pr_number as number) < 1) {
    throw new Error("pr_number must be a positive integer");
  }
  if (typeof raw.expected_head_sha !== "string" || !SHA_RE.test(raw.expected_head_sha)) {
    throw new Error("expected_head_sha must be a lowercase 40-character commit SHA");
  }
  assertSafeText(raw.text);
  if (typeof raw.dry_run !== "boolean") throw new Error("dry_run must be a boolean");
  if (typeof raw.client_idempotency_key !== "string" || !IDEMPOTENCY_RE.test(raw.client_idempotency_key)) {
    throw new Error("client_idempotency_key must be 16-128 safe ASCII characters");
  }
  if (
    typeof raw.justification !== "string" ||
    raw.justification.trim().length === 0 ||
    utf8Bytes(raw.justification) > MAX_JUSTIFICATION_BYTES ||
    /\0|[\u0001-\u0008\u000B\u000C\u000E-\u001F\u007F]/u.test(raw.justification)
  ) {
    throw new Error("justification must be nonempty, bounded, and free of control characters");
  }
  const base: CommentRequestBase = {
    repo: raw.repo,
    pr_number: raw.pr_number as number,
    expected_head_sha: raw.expected_head_sha,
    text: raw.text,
    dry_run: raw.dry_run,
    client_idempotency_key: raw.client_idempotency_key,
    justification: raw.justification,
    audit_metadata: parseAuditMetadata(raw.audit_metadata),
  };
  if (capability === REVIEW_THREAD_REPLY_METHOD) {
    if (!Number.isSafeInteger(raw.review_comment_id) || (raw.review_comment_id as number) < 1) {
      throw new Error("review_comment_id must be a positive integer");
    }
    return { ...base, review_comment_id: raw.review_comment_id as number };
  }
  return base;
}

function validateRepo(repo: string): void {
  if (repo !== repo.normalize("NFKC")) throw new Error("repo must use canonical Unicode form");
  if (!REPO_RE.test(repo)) throw new Error("repo must be a canonical fabrica-land owner/repository name");
  const name = repo.split("/")[1]!;
  if (name === "." || name === ".." || name.includes("..")) {
    throw new Error("repo contains a forbidden path segment");
  }
}

function redactAuditText(value: string): string {
  let redacted = value;
  for (const pattern of LIKELY_SECRET_PATTERNS) {
    redacted = redacted.replace(new RegExp(pattern.source, `${pattern.flags}g`), "[REDACTED]");
  }
  return redacted;
}

function payloadHash(capability: CommentCapability, request: ParsedRequest): string {
  return sha256(JSON.stringify({ capability, ...request, dry_run: false }));
}

function reservationKey(capability: CommentCapability, caller: string, clientKey: string): string {
  return sha256(`${capability}\0${caller}\0${clientKey}`);
}

function rateScope(capability: CommentCapability, request: ParsedRequest): string {
  if (capability === REVIEW_THREAD_REPLY_METHOD) {
    return `${request.repo}\0${request.pr_number}\0${(request as ReviewThreadReplyRequest).review_comment_id}`;
  }
  return `${request.repo}\0${request.pr_number}`;
}

export class GithubCommentCapabilitiesBroker {
  private readonly db: Database;
  private readonly fetchImpl: typeof globalThis.fetch;
  private readonly now: () => number;
  private readonly auditTextPolicy: AuditTextPolicy;
  private readonly prCommentMinimumIntervalMs: number;
  private readonly reviewReplyMinimumIntervalMs: number;

  constructor(private readonly config: GithubCommentCapabilitiesConfig) {
    if (config.allowedRepos.size === 0) throw new Error("at least one repository must be allowlisted");
    for (const repo of config.allowedRepos) validateRepo(repo);
    for (const capability of COMMENT_CAPABILITIES) {
      const callers = config.allowedCapabilityCallers.get(capability) ?? new Map();
      for (const [source, keys] of callers) {
        if (!/^[A-Za-z0-9][A-Za-z0-9@._-]{0,127}$/.test(source) || keys.size === 0) {
          throw new Error(`capability '${capability}' has an invalid caller grant`);
        }
        for (const key of keys) {
          if (key.length < 16 || key.length > 256 || !/^[A-Za-z0-9+/_=-]+$/.test(key)) {
            throw new Error(`capability '${capability}' caller '${source}' has an invalid public key`);
          }
        }
      }
    }
    this.fetchImpl = config.fetchImpl ?? fetch;
    this.now = config.now ?? Date.now;
    this.auditTextPolicy = config.auditTextPolicy ?? "hash";
    this.prCommentMinimumIntervalMs = config.prCommentMinimumIntervalMs ?? 60 * 60_000;
    this.reviewReplyMinimumIntervalMs = config.reviewReplyMinimumIntervalMs ?? 30 * 60_000;
    if (!new Set<AuditTextPolicy>(["hash", "redacted_full"]).has(this.auditTextPolicy)) {
      throw new Error("auditTextPolicy must be 'hash' or 'redacted_full'");
    }
    for (const interval of [this.prCommentMinimumIntervalMs, this.reviewReplyMinimumIntervalMs]) {
      if (!Number.isSafeInteger(interval) || interval < 1) throw new Error("rate interval must be positive");
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
      CREATE TABLE IF NOT EXISTS github_comment_requests (
        request_key TEXT PRIMARY KEY,
        capability TEXT NOT NULL,
        caller TEXT NOT NULL,
        client_idempotency_key TEXT NOT NULL,
        payload_hash TEXT NOT NULL,
        rate_scope TEXT NOT NULL,
        repo TEXT NOT NULL,
        pr_number INTEGER NOT NULL,
        head_sha TEXT NOT NULL,
        status TEXT NOT NULL,
        requested_at INTEGER NOT NULL,
        posted_at INTEGER,
        comment_id INTEGER,
        comment_url TEXT,
        error TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_github_comment_rate
      ON github_comment_requests(capability, caller, rate_scope, posted_at);
    `);
  }

  close(): void {
    this.db.close();
  }

  private isCallerAllowed(capability: CommentCapability, caller: VerifiedCaller): boolean {
    const keys = this.config.allowedCapabilityCallers.get(capability)?.get(caller.source);
    return Boolean(caller.sourcePubkey && keys?.has(caller.sourcePubkey));
  }

  private audit(event: Record<string, unknown>): void {
    assertOwnerOnlyFile(this.config.auditFile, "audit file");
    appendFileSync(
      this.config.auditFile,
      `${JSON.stringify({ at: new Date(this.now()).toISOString(), ...event })}\n`,
      { encoding: "utf8", mode: 0o600 },
    );
  }

  private textAuditFields(text: unknown): Record<string, unknown> {
    if (typeof text !== "string") return { text_present: false };
    const fields: Record<string, unknown> = {
      text_present: true,
      text_bytes: utf8Bytes(text),
      text_sha256: sha256(text),
    };
    if (this.auditTextPolicy === "redacted_full") {
      fields.text = utf8Bytes(text) <= MAX_TEXT_BYTES
        ? redactAuditText(text)
        : "[OVERSIZE TEXT OMITTED]";
    }
    return fields;
  }

  private githubPath(repo: string, suffix: string): string {
    const [owner, name] = repo.split("/");
    return `/repos/${encodeURIComponent(owner!)}/${encodeURIComponent(name!)}${suffix}`;
  }

  private async githubJson<T>(token: string, path: string, init: RequestInit = {}): Promise<T> {
    if (!path.startsWith("/") || path.startsWith("//") || path.includes("\\")) {
      throw new Error("internal GitHub path must be relative and canonical");
    }
    const headers = new Headers(init.headers);
    headers.set("Authorization", `Bearer ${token}`);
    headers.set("Accept", "application/vnd.github+json");
    headers.set("Content-Type", "application/json");
    headers.set("User-Agent", "agiterra-github-comment-broker");
    headers.set("X-GitHub-Api-Version", "2022-11-28");
    const response = await this.fetchImpl(`${GITHUB_API}${path}`, {
      ...init,
      headers,
      redirect: "error",
    });
    if (!response.ok) throw new Error(`GitHub API request failed (${response.status})`);
    return (await response.json()) as T;
  }

  private async validateIdentityAndPr(token: string, request: ParsedRequest): Promise<GithubPr> {
    const user = await this.githubJson<{ login?: string }>(token, "/user");
    if (user.login !== EXPECTED_GITHUB_LOGIN) {
      throw new Error("broker GitHub credential identity drifted from the required operator login");
    }
    const pr = await this.githubJson<GithubPr>(
      token,
      this.githubPath(request.repo, `/pulls/${request.pr_number}`),
    );
    if (pr.number !== request.pr_number || pr.base?.repo?.full_name !== request.repo) {
      throw new Error("GitHub target identity drifted from the requested repository/PR");
    }
    if (pr.state !== "open") throw new Error("target PR is not open");
    if (pr.head?.sha !== request.expected_head_sha) {
      throw new Error("target PR head drifted from expected_head_sha");
    }
    return pr;
  }

  private expectedPullRequestUrl(request: ParsedRequest): string {
    return `${GITHUB_API}${this.githubPath(request.repo, `/pulls/${request.pr_number}`)}`;
  }

  private async validateThreadAnchor(
    token: string,
    request: ReviewThreadReplyRequest,
  ): Promise<GithubReviewComment> {
    const anchor = await this.githubJson<GithubReviewComment>(
      token,
      this.githubPath(request.repo, `/pulls/comments/${request.review_comment_id}`),
    );
    if (anchor.id !== request.review_comment_id) throw new Error("review-thread anchor identity drifted");
    if (anchor.pull_request_url !== this.expectedPullRequestUrl(request)) {
      throw new Error("review-thread anchor does not belong to the requested repository/PR");
    }
    if (anchor.in_reply_to_id !== undefined) {
      throw new Error("review_comment_id must identify the root comment of a review thread");
    }
    if (
      anchor.commit_id !== request.expected_head_sha ||
      !Number.isSafeInteger(anchor.position) ||
      (anchor.position as number) < 1
    ) {
      throw new Error("review-thread anchor is outdated for the expected PR head");
    }
    return anchor;
  }

  private stored(key: string): StoredRequest | null {
    return this.db
      .query<StoredRequest, [string]>(
        "SELECT status, payload_hash, comment_id, comment_url FROM github_comment_requests WHERE request_key = ?",
      )
      .get(key) ?? null;
  }

  private minimumInterval(capability: CommentCapability): number {
    return capability === PR_COMMENT_METHOD
      ? this.prCommentMinimumIntervalMs
      : this.reviewReplyMinimumIntervalMs;
  }

  private decideAndReserve(
    capability: CommentCapability,
    request: ParsedRequest,
    caller: string,
    hash: string,
    now: number,
  ): ReservationDecision {
    const key = reservationKey(capability, caller, request.client_idempotency_key);
    const scope = rateScope(capability, request);
    const transaction = this.db.transaction(() => {
      const existing = this.stored(key);
      if (existing && existing.payload_hash !== hash) {
        throw new Error("client_idempotency_key was already used for a different payload");
      }
      if (existing?.status === "posted") return { kind: "idempotent", key, previous: existing } as const;
      if (existing?.status === "processing" || existing?.status === "unsafe_posted") {
        throw new Error("request is in progress or has an ambiguous prior outcome; operator review is required");
      }

      const ambiguous = this.db
        .query<{ status: string }, [string, string, string]>(
          `SELECT status FROM github_comment_requests
           WHERE capability = ? AND caller = ? AND rate_scope = ?
             AND status IN ('processing', 'unsafe_posted')
           LIMIT 1`,
        )
        .get(capability, caller, scope);
      if (ambiguous) throw new Error("comment target has an in-progress or ambiguous request");

      const latest = this.db
        .query<{ posted_at: number | null }, [string, string, string]>(
          `SELECT MAX(posted_at) AS posted_at FROM github_comment_requests
           WHERE capability = ? AND caller = ? AND rate_scope = ? AND status = 'posted'`,
        )
        .get(capability, caller, scope)?.posted_at ?? null;
      if (latest !== null && now - latest < this.minimumInterval(capability)) {
        throw new Error("comment capability is rate-limited for this caller and target");
      }

      if (existing && existing.status !== "failed") {
        throw new Error(`stored comment request has unsupported state '${existing.status}'`);
      }
      if (existing) {
        const update = this.db
          .query(
            `UPDATE github_comment_requests SET
               payload_hash = ?, rate_scope = ?, repo = ?, pr_number = ?, head_sha = ?,
               status = 'processing', requested_at = ?, posted_at = NULL,
               comment_id = NULL, comment_url = NULL, error = NULL
             WHERE request_key = ? AND status = 'failed' AND payload_hash = ?`,
          )
          .run(
            hash,
            scope,
            request.repo,
            request.pr_number,
            request.expected_head_sha,
            now,
            key,
            hash,
          );
        if (update.changes !== 1) throw new Error("failed comment reservation lost an atomic race");
      } else {
        this.db
          .query(
            `INSERT INTO github_comment_requests
             (request_key, capability, caller, client_idempotency_key, payload_hash, rate_scope,
              repo, pr_number, head_sha, status, requested_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'processing', ?)`,
          )
          .run(
            key,
            capability,
            caller,
            request.client_idempotency_key,
            hash,
            scope,
            request.repo,
            request.pr_number,
            request.expected_head_sha,
            now,
          );
      }
      return { kind: "reserved", key } as const;
    });
    return transaction.immediate();
  }

  private markFailed(key: string, error: unknown): void {
    this.db
      .query(
        "UPDATE github_comment_requests SET status = 'failed', error = ? WHERE request_key = ? AND status = 'processing'",
      )
      .run(safeAuditError(error), key);
  }

  private markUnsafe(key: string, comment: GithubIssueComment, error: unknown): void {
    this.db
      .query(
        `UPDATE github_comment_requests SET status = 'unsafe_posted', posted_at = ?,
         comment_id = ?, comment_url = ?, error = ?
         WHERE request_key = ? AND status = 'processing'`,
      )
      .run(this.now(), comment.id ?? null, comment.html_url ?? null, safeAuditError(error), key);
  }

  private markPosted(key: string, comment: GithubIssueComment): void {
    const update = this.db
      .query(
        `UPDATE github_comment_requests SET status = 'posted', posted_at = ?,
         comment_id = ?, comment_url = ?, error = NULL
         WHERE request_key = ? AND status = 'processing'`,
      )
      .run(this.now(), comment.id!, comment.html_url ?? null, key);
    if (update.changes !== 1) throw new Error("comment request could not commit its terminal state");
  }

  async request(
    capability: CommentCapability,
    input: unknown,
    caller: VerifiedCaller,
  ): Promise<GithubCommentCapabilityResult> {
    if (!COMMENT_CAPABILITIES.includes(capability)) throw new Error("unsupported comment capability");
    const requestId = crypto.randomUUID();
    const raw = input && typeof input === "object" ? input as Record<string, unknown> : {};
    this.audit({
      event: "github_comment_request",
      request_id: requestId,
      capability,
      caller: caller.source,
      verified_key_present: Boolean(caller.sourcePubkey),
      repo: typeof raw.repo === "string" ? raw.repo.slice(0, 256) : null,
      pr_number: typeof raw.pr_number === "number" ? raw.pr_number : null,
      dry_run: raw.dry_run === true,
      tracking_ref: (() => {
        const value = raw.audit_metadata && typeof raw.audit_metadata === "object"
          ? (raw.audit_metadata as Record<string, unknown>).tracking_ref
          : null;
        return typeof value === "string" && TRACKING_RE.test(value) ? value : null;
      })(),
      ...this.textAuditFields(raw.text),
    });

    let key: string | null = null;
    let reserved = false;
    let postAttempted = false;
    try {
      if (!this.isCallerAllowed(capability, caller)) {
        throw new Error(`caller is not authorized for capability '${capability}'`);
      }
      const parsed = parseRequest(capability, input);
      validateRepo(parsed.repo);
      if (!this.config.allowedRepos.has(parsed.repo)) {
        throw new Error(`repository '${parsed.repo}' is not allowlisted`);
      }
      const hash = payloadHash(capability, parsed);
      this.audit({
        event: "github_comment_validated_request",
        request_id: requestId,
        capability,
        caller: caller.source,
        repo: parsed.repo,
        pr_number: parsed.pr_number,
        head_sha: parsed.expected_head_sha,
        tracking_ref: parsed.audit_metadata.tracking_ref,
        reason_code: parsed.audit_metadata.reason_code,
        justification_sha256: sha256(parsed.justification),
        client_idempotency_key_sha256: sha256(parsed.client_idempotency_key),
        ...this.textAuditFields(parsed.text),
      });

      if (parsed.dry_run) {
        const token = await this.config.tokenSource.getToken();
        await this.validateIdentityAndPr(token, parsed);
        if (capability === REVIEW_THREAD_REPLY_METHOD) {
          await this.validateThreadAnchor(token, parsed as ReviewThreadReplyRequest);
        }
        const result: GithubCommentCapabilityResult = {
          request_id: requestId,
          capability,
          repo: parsed.repo,
          pr_number: parsed.pr_number,
          head_sha: parsed.expected_head_sha,
          review_comment_id:
            capability === REVIEW_THREAD_REPLY_METHOD
              ? (parsed as ReviewThreadReplyRequest).review_comment_id
              : undefined,
          text_sha256: sha256(parsed.text),
          dry_run: true,
          would_post: true,
          github_login: EXPECTED_GITHUB_LOGIN,
        };
        this.audit({ event: "github_comment_result", outcome: "dry_run", caller: caller.source, ...result });
        return result;
      }

      const decision = this.decideAndReserve(capability, parsed, caller.source, hash, this.now());
      key = decision.key;
      if (decision.kind === "idempotent") {
        const result: GithubCommentCapabilityResult = {
          request_id: requestId,
          capability,
          repo: parsed.repo,
          pr_number: parsed.pr_number,
          head_sha: parsed.expected_head_sha,
          review_comment_id:
            capability === REVIEW_THREAD_REPLY_METHOD
              ? (parsed as ReviewThreadReplyRequest).review_comment_id
              : undefined,
          text_sha256: sha256(parsed.text),
          dry_run: false,
          posted: true,
          idempotent: true,
          comment_id: decision.previous.comment_id ?? undefined,
          comment_url: decision.previous.comment_url ?? undefined,
          github_login: EXPECTED_GITHUB_LOGIN,
        };
        this.audit({ event: "github_comment_result", outcome: "idempotent", caller: caller.source, ...result });
        return result;
      }
      reserved = true;

      const token = await this.config.tokenSource.getToken();
      await this.validateIdentityAndPr(token, parsed);
      let anchor: GithubReviewComment | undefined;
      if (capability === REVIEW_THREAD_REPLY_METHOD) {
        anchor = await this.validateThreadAnchor(token, parsed as ReviewThreadReplyRequest);
      }

      postAttempted = true;
      const created = capability === PR_COMMENT_METHOD
        ? await this.githubJson<GithubIssueComment>(
          token,
          this.githubPath(parsed.repo, `/issues/${parsed.pr_number}/comments`),
          { method: "POST", body: JSON.stringify({ body: parsed.text }) },
        )
        : await this.githubJson<GithubReviewComment>(
          token,
          this.githubPath(
            parsed.repo,
            `/pulls/${parsed.pr_number}/comments/${(parsed as ReviewThreadReplyRequest).review_comment_id}/replies`,
          ),
          { method: "POST", body: JSON.stringify({ body: parsed.text }) },
        );
      if (!Number.isSafeInteger(created.id)) {
        const error = new Error("GitHub comment creation response did not contain a valid comment id");
        this.markUnsafe(key, created, error);
        throw error;
      }

      const readback = capability === PR_COMMENT_METHOD
        ? await this.githubJson<GithubIssueComment>(
          token,
          this.githubPath(parsed.repo, `/issues/comments/${created.id}`),
        )
        : await this.githubJson<GithubReviewComment>(
          token,
          this.githubPath(parsed.repo, `/pulls/comments/${created.id}`),
        );
      const finalPr = await this.validateIdentityAndPr(token, parsed);
      if (
        readback.id !== created.id ||
        readback.body !== parsed.text ||
        readback.user?.login !== EXPECTED_GITHUB_LOGIN ||
        finalPr.head?.sha !== parsed.expected_head_sha
      ) {
        const error = new Error("GitHub comment readback author/body/head mismatch");
        this.markUnsafe(key, readback.id ? readback : created, error);
        throw error;
      }
      if (capability === REVIEW_THREAD_REPLY_METHOD) {
        const reply = readback as GithubReviewComment;
        const threadRequest = parsed as ReviewThreadReplyRequest;
        if (
          reply.pull_request_url !== this.expectedPullRequestUrl(parsed) ||
          reply.in_reply_to_id !== threadRequest.review_comment_id ||
          reply.commit_id !== parsed.expected_head_sha
        ) {
          const error = new Error("GitHub review-thread reply readback anchor mismatch");
          this.markUnsafe(key, reply, error);
          throw error;
        }
        const finalAnchor = await this.validateThreadAnchor(token, threadRequest);
        if (finalAnchor.id !== anchor?.id) {
          const error = new Error("review-thread anchor drifted during publication");
          this.markUnsafe(key, reply, error);
          throw error;
        }
      }

      this.markPosted(key, readback);
      const result: GithubCommentCapabilityResult = {
        request_id: requestId,
        capability,
        repo: parsed.repo,
        pr_number: parsed.pr_number,
        head_sha: parsed.expected_head_sha,
        review_comment_id:
          capability === REVIEW_THREAD_REPLY_METHOD
            ? (parsed as ReviewThreadReplyRequest).review_comment_id
            : undefined,
        text_sha256: sha256(parsed.text),
        dry_run: false,
        posted: true,
        idempotent: false,
        comment_id: readback.id,
        comment_url: readback.html_url,
        github_login: EXPECTED_GITHUB_LOGIN,
      };
      this.audit({ event: "github_comment_result", outcome: "posted", caller: caller.source, ...result });
      return result;
    } catch (error) {
      if (reserved && key) {
        const current = this.stored(key);
        if (current?.status === "processing") {
          if (postAttempted) this.markUnsafe(key, {}, error);
          else this.markFailed(key, error);
        }
      }
      this.audit({
        event: "github_comment_result",
        request_id: requestId,
        capability,
        caller: caller.source,
        outcome: "refused_or_failed",
        error: safeAuditError(error),
      });
      throw error;
    }
  }
}

export function parseCapabilityCallers(value: string): CapabilityCallerMap {
  const raw = JSON.parse(value) as Record<string, unknown>;
  const result = new Map<CommentCapability, ReadonlyMap<string, ReadonlySet<string>>>();
  for (const key of Object.keys(raw)) {
    if (!COMMENT_CAPABILITIES.includes(key as CommentCapability)) {
      throw new Error(`unsupported comment capability '${key}'`);
    }
  }
  for (const capability of COMMENT_CAPABILITIES) {
    const grants = raw[capability] ?? {};
    if (!grants || typeof grants !== "object" || Array.isArray(grants)) {
      throw new Error(`capability '${capability}' grants must be an object`);
    }
    const callers = new Map<string, ReadonlySet<string>>();
    for (const [source, keys] of Object.entries(grants as Record<string, unknown>)) {
      if (!Array.isArray(keys) || keys.some((key) => typeof key !== "string")) {
        throw new Error(`capability '${capability}' caller '${source}' must map to public keys`);
      }
      callers.set(source, new Set(keys as string[]));
    }
    result.set(capability, callers);
  }
  return result;
}
