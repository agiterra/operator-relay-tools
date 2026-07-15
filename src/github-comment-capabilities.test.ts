import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { createHash } from "node:crypto";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  GithubCommentCapabilitiesBroker,
  PR_COMMENT_METHOD,
  REVIEW_THREAD_REPLY_METHOD,
  parseCapabilityCallers,
  type AuditTextPolicy,
  type CapabilityCallerMap,
  type PrCommentRequest,
  type ReviewThreadReplyRequest,
} from "./github-comment-capabilities.js";
import { FineGrainedPatFileTokenSource } from "./github-token-source.js";

const HEAD_A = "a".repeat(40);
const HEAD_B = "b".repeat(40);
const REPO = "fabrica-land/soil-app";
const CALLER = { source: "brioche", sourcePubkey: "verified-public-key-0001" };
const SECOND_CALLER = { source: "vacherin", sourcePubkey: "verified-public-key-0002" };
const ANCHOR_ID = 7001;
const PR_COMMENT_ID = 9001;
const REPLY_ID = 9002;

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "github-comment-capabilities-"));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

type FakeOptions = {
  login?: string;
  repo?: string;
  state?: string;
  currentHead?: string;
  postThrows?: boolean;
  driftAfterPost?: boolean;
  anchorPr?: number;
  anchorRepo?: string;
  anchorCommit?: string;
  anchorPosition?: number | null;
  anchorIsReply?: boolean;
  anchorDeletedAfterPost?: boolean;
  readbackBody?: string;
  readbackLogin?: string;
  replyAnchorId?: number;
};

function fakeGithub(options: FakeOptions = {}) {
  let posted = false;
  let head = options.currentHead ?? HEAD_A;
  const calls: Array<{ url: string; method: string; auth: string | null; body?: unknown }> = [];
  const pullUrl = (pr = 42, repo = REPO) => `https://api.github.com/repos/${repo}/pulls/${pr}`;
  const fetchImpl = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = String(input);
    const method = init?.method ?? "GET";
    const headers = new Headers(init?.headers);
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
    calls.push({ url, method, auth: headers.get("authorization"), body });

    if (url === "https://api.github.com/user") {
      return Response.json({ login: options.login ?? "mividtim" });
    }
    if (url.endsWith("/pulls/42")) {
      return Response.json({
        number: 42,
        state: options.state ?? "open",
        head: { sha: posted && options.driftAfterPost ? HEAD_B : head },
        base: { repo: { full_name: options.repo ?? REPO } },
      });
    }
    if (url.endsWith(`/pulls/comments/${ANCHOR_ID}`)) {
      if (posted && options.anchorDeletedAfterPost) return new Response("gone", { status: 404 });
      return Response.json({
        id: ANCHOR_ID,
        body: "review finding",
        html_url: `https://github.com/${REPO}/pull/42#discussion_r${ANCHOR_ID}`,
        user: { login: "coderabbitai[bot]" },
        pull_request_url: pullUrl(options.anchorPr ?? 42, options.anchorRepo ?? REPO),
        commit_id: options.anchorCommit ?? HEAD_A,
        position: options.anchorPosition === undefined ? 5 : options.anchorPosition,
        ...(options.anchorIsReply ? { in_reply_to_id: 6999 } : {}),
      });
    }
    if (url.endsWith("/issues/42/comments") && method === "POST") {
      posted = true;
      if (options.postThrows) throw new Error("simulated ambiguous issue-comment transport failure");
      return Response.json({
        id: PR_COMMENT_ID,
        body: (body as { body: string }).body,
        html_url: `https://github.com/${REPO}/pull/42#issuecomment-${PR_COMMENT_ID}`,
        user: { login: "mividtim" },
      });
    }
    if (url.endsWith(`/issues/comments/${PR_COMMENT_ID}`)) {
      return Response.json({
        id: PR_COMMENT_ID,
        body: options.readbackBody ?? (calls.find((call) => call.method === "POST")?.body as { body: string }).body,
        html_url: `https://github.com/${REPO}/pull/42#issuecomment-${PR_COMMENT_ID}`,
        user: { login: options.readbackLogin ?? "mividtim" },
      });
    }
    if (url.endsWith(`/pulls/42/comments/${ANCHOR_ID}/replies`) && method === "POST") {
      posted = true;
      if (options.postThrows) throw new Error("simulated ambiguous review-reply transport failure");
      return Response.json({
        id: REPLY_ID,
        body: (body as { body: string }).body,
        html_url: `https://github.com/${REPO}/pull/42#discussion_r${REPLY_ID}`,
        user: { login: "mividtim" },
        pull_request_url: pullUrl(),
        commit_id: HEAD_A,
        position: 5,
        in_reply_to_id: ANCHOR_ID,
      });
    }
    if (url.endsWith(`/pulls/comments/${REPLY_ID}`)) {
      const latestPost = calls.filter((call) => call.method === "POST").at(-1);
      return Response.json({
        id: REPLY_ID,
        body: options.readbackBody ?? (latestPost?.body as { body: string }).body,
        html_url: `https://github.com/${REPO}/pull/42#discussion_r${REPLY_ID}`,
        user: { login: options.readbackLogin ?? "mividtim" },
        pull_request_url: pullUrl(),
        commit_id: HEAD_A,
        position: 5,
        in_reply_to_id: options.replyAnchorId ?? ANCHOR_ID,
      });
    }
    return new Response("not found", { status: 404 });
  };
  return {
    fetchImpl: fetchImpl as typeof fetch,
    calls,
    posts: () => calls.filter((call) => call.method === "POST"),
    setHead: (value: string) => { head = value; },
  };
}

function grants(options: { pr?: boolean; reply?: boolean } = { pr: true, reply: true }): CapabilityCallerMap {
  return new Map([
    [
      PR_COMMENT_METHOD,
      new Map(options.pr ? [
        [CALLER.source, new Set([CALLER.sourcePubkey])],
        [SECOND_CALLER.source, new Set([SECOND_CALLER.sourcePubkey])],
      ] : []),
    ],
    [
      REVIEW_THREAD_REPLY_METHOD,
      new Map(options.reply ? [
        [CALLER.source, new Set([CALLER.sourcePubkey])],
        [SECOND_CALLER.source, new Set([SECOND_CALLER.sourcePubkey])],
      ] : []),
    ],
  ]);
}

function prRequest(overrides: Partial<PrCommentRequest> = {}): PrCommentRequest {
  return {
    repo: REPO,
    pr_number: 42,
    expected_head_sha: HEAD_A,
    text: "Review response ✅\n\n**Fixed** @coderabbitai — see https://example.test/a?b=1#c",
    dry_run: true,
    client_idempotency_key: "request-0000000001",
    justification: "Respond to an independently reviewed current-head finding.",
    audit_metadata: { tracking_ref: "AGI-24", reason_code: "review_response" },
    ...overrides,
  };
}

function replyRequest(overrides: Partial<ReviewThreadReplyRequest> = {}): ReviewThreadReplyRequest {
  return {
    ...prRequest(),
    client_idempotency_key: "reply-00000000001",
    review_comment_id: ANCHOR_ID,
    ...overrides,
  };
}

function makeBroker(
  fake = fakeGithub(),
  options: {
    callerGrants?: CapabilityCallerMap;
    auditTextPolicy?: AuditTextPolicy;
    prInterval?: number;
    replyInterval?: number;
  } = {},
) {
  const tokenFile = join(dir, "github-token");
  const stateFile = join(dir, "state", "requests.sqlite");
  const auditFile = join(dir, "audit", "requests.jsonl");
  writeFileSync(tokenFile, "github_pat_owner-secret-token\n", { mode: 0o600 });
  chmodSync(tokenFile, 0o600);
  let now = 1_700_000_000_000;
  const broker = new GithubCommentCapabilitiesBroker({
    allowedRepos: new Set([REPO, "fabrica-land/fabrica-v3-api"]),
    allowedCapabilityCallers: options.callerGrants ?? grants(),
    tokenSource: new FineGrainedPatFileTokenSource(tokenFile),
    stateFile,
    auditFile,
    auditTextPolicy: options.auditTextPolicy ?? "hash",
    prCommentMinimumIntervalMs: options.prInterval ?? 60_000,
    reviewReplyMinimumIntervalMs: options.replyInterval ?? 60_000,
    fetchImpl: fake.fetchImpl,
    now: () => now,
  });
  return {
    broker,
    fake,
    stateFile,
    auditFile,
    tokenFile,
    advance: (ms: number) => { now += ms; },
  };
}

describe("GithubCommentCapabilitiesBroker", () => {
  test("empty default capability configuration grants no arbitrary-comment authority", async () => {
    const setup = makeBroker(undefined, { callerGrants: parseCapabilityCallers("{}") });
    await expect(setup.broker.request(PR_COMMENT_METHOD, prRequest(), CALLER)).rejects.toThrow(
      /not authorized/,
    );
    await expect(
      setup.broker.request(REVIEW_THREAD_REPLY_METHOD, replyRequest(), CALLER),
    ).rejects.toThrow(/not authorized/);
    expect(setup.fake.calls).toHaveLength(0);
    setup.broker.close();
  });

  test("keeps PR-comment and review-reply caller capabilities independent", async () => {
    const setup = makeBroker(undefined, { callerGrants: grants({ pr: true, reply: false }) });
    await expect(setup.broker.request(PR_COMMENT_METHOD, prRequest(), CALLER)).resolves.toMatchObject({
      dry_run: true,
    });
    await expect(
      setup.broker.request(REVIEW_THREAD_REPLY_METHOD, replyRequest(), CALLER),
    ).rejects.toThrow(/not authorized/);
    setup.broker.close();
  });

  test("posts exact arbitrary Unicode, markdown, mentions, and URLs as a PR comment", async () => {
    const setup = makeBroker();
    const request = prRequest({ dry_run: false });
    const result = await setup.broker.request(PR_COMMENT_METHOD, request, CALLER);
    expect(result).toMatchObject({ posted: true, idempotent: false, comment_id: PR_COMMENT_ID });
    expect(setup.fake.posts()).toHaveLength(1);
    expect(setup.fake.posts()[0]!.url).toEndWith("/issues/42/comments");
    expect(setup.fake.posts()[0]!.body).toEqual({ body: request.text });
    setup.broker.close();
  });

  test("constructs only the exact review-thread reply endpoint and verifies the anchor", async () => {
    const setup = makeBroker();
    const request = replyRequest({ dry_run: false });
    const result = await setup.broker.request(REVIEW_THREAD_REPLY_METHOD, request, CALLER);
    expect(result).toMatchObject({
      posted: true,
      comment_id: REPLY_ID,
      review_comment_id: ANCHOR_ID,
    });
    expect(setup.fake.posts()).toHaveLength(1);
    expect(setup.fake.posts()[0]!.url).toEndWith(`/pulls/42/comments/${ANCHOR_ID}/replies`);
    expect(setup.fake.posts()[0]!.body).toEqual({ body: request.text });
    setup.broker.close();
  });

  test("dry-run validates the target and thread without reserving or posting", async () => {
    const setup = makeBroker();
    const result = await setup.broker.request(REVIEW_THREAD_REPLY_METHOD, replyRequest(), CALLER);
    expect(result).toMatchObject({ dry_run: true, would_post: true });
    expect(setup.fake.posts()).toHaveLength(0);
    setup.broker.close();
  });

  test("rejects empty, oversized, control-character, and likely-secret text", async () => {
    const setup = makeBroker();
    const invalid = [
      "   ",
      "x".repeat(8193),
      "bad\0text",
      `do not post github_pat_${"a".repeat(30)}`,
    ];
    for (const text of invalid) {
      await expect(setup.broker.request(PR_COMMENT_METHOD, prRequest({ text }), CALLER)).rejects.toThrow();
    }
    expect(setup.fake.calls).toHaveLength(0);
    setup.broker.close();
  });

  test("rejects schema injection, SSRF, repo spoofing, and idempotency-key injection", async () => {
    const setup = makeBroker();
    const inputs = [
      { ...prRequest(), arbitrary: "field" },
      prRequest({ justification: "x".repeat(1025) }),
      prRequest({
        audit_metadata: {
          tracking_ref: "AGI-24",
          reason_code: "not-allowed" as "other",
        },
      }),
      {
        ...prRequest(),
        audit_metadata: { tracking_ref: "AGI-24", reason_code: "other", extra: "field" },
      },
      prRequest({ repo: "https://evil.invalid/fabrica-land/soil-app" }),
      prRequest({ repo: "fabrica-land/soil-app/../../evil" }),
      prRequest({ repo: "evil/soil-app" }),
      prRequest({ client_idempotency_key: "request\nheader:value" }),
    ];
    for (const input of inputs) {
      await expect(setup.broker.request(PR_COMMENT_METHOD, input, CALLER)).rejects.toThrow();
    }
    expect(setup.fake.calls).toHaveLength(0);
    setup.broker.close();
  });

  test("fails closed for wrong-PR, wrong-repo, outdated, and non-root thread anchors", async () => {
    for (const options of [
      { anchorPr: 43 },
      { anchorRepo: "fabrica-land/fabrica-v3-api" },
      { anchorCommit: HEAD_B },
      { anchorPosition: null },
      { anchorIsReply: true },
    ]) {
      const setup = makeBroker(fakeGithub(options));
      await expect(
        setup.broker.request(REVIEW_THREAD_REPLY_METHOD, replyRequest(), CALLER),
      ).rejects.toThrow(/anchor|outdated|root/);
      expect(setup.fake.posts()).toHaveLength(0);
      setup.broker.close();
      rmSync(dir, { recursive: true, force: true });
      dir = mkdtempSync(join(tmpdir(), "github-comment-capabilities-"));
    }
  });

  test("fails closed for a closed PR before either comment capability posts", async () => {
    const setup = makeBroker(fakeGithub({ state: "closed" }));
    await expect(setup.broker.request(PR_COMMENT_METHOD, prRequest(), CALLER)).rejects.toThrow(
      /not open/,
    );
    await expect(
      setup.broker.request(REVIEW_THREAD_REPLY_METHOD, replyRequest(), CALLER),
    ).rejects.toThrow(/not open/);
    expect(setup.fake.posts()).toHaveLength(0);
    setup.broker.close();
  });

  test("caller-provided request headers cannot override broker Authorization", async () => {
    const setup = makeBroker();
    const hidden = setup.broker as unknown as {
      githubJson<T>(token: string, path: string, init?: RequestInit): Promise<T>;
    };
    await hidden.githubJson("github_pat_owner-secret-token", "/user", {
      headers: { authorization: "Bearer attacker-controlled" },
    });
    expect(setup.fake.calls[0]!.auth).toBe("Bearer github_pat_owner-secret-token");
    setup.broker.close();
  });

  test("is idempotent for an identical posted payload and rejects key reuse with drift", async () => {
    const setup = makeBroker();
    const request = prRequest({ dry_run: false });
    await setup.broker.request(PR_COMMENT_METHOD, request, CALLER);
    const duplicate = await setup.broker.request(PR_COMMENT_METHOD, request, CALLER);
    expect(duplicate).toMatchObject({ posted: true, idempotent: true, comment_id: PR_COMMENT_ID });
    await expect(
      setup.broker.request(PR_COMMENT_METHOD, { ...request, text: "different body" }, CALLER),
    ).rejects.toThrow(/different payload/);
    expect(setup.fake.posts()).toHaveLength(1);
    setup.broker.close();
  });

  test("serializes concurrent identical requests into one post", async () => {
    const setup = makeBroker();
    const request = prRequest({ dry_run: false });
    const results = await Promise.allSettled([
      setup.broker.request(PR_COMMENT_METHOD, request, CALLER),
      setup.broker.request(PR_COMMENT_METHOD, request, CALLER),
    ]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
    expect(setup.fake.posts()).toHaveLength(1);
    setup.broker.close();
  });

  test("serializes distinct-id same-target races and enforces the per-capability rate limit", async () => {
    const setup = makeBroker();
    const results = await Promise.allSettled([
      setup.broker.request(PR_COMMENT_METHOD, prRequest({ dry_run: false }), CALLER),
      setup.broker.request(
        PR_COMMENT_METHOD,
        prRequest({ dry_run: false, client_idempotency_key: "request-0000000002" }),
        CALLER,
      ),
    ]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
    await expect(
      setup.broker.request(
        PR_COMMENT_METHOD,
        prRequest({ dry_run: false, client_idempotency_key: "request-0000000003" }),
        CALLER,
      ),
    ).rejects.toThrow(/rate-limited/);
    expect(setup.fake.posts()).toHaveLength(1);
    setup.broker.close();
  });

  test("keeps PR-comment and review-reply rate/idempotency scopes independent", async () => {
    const setup = makeBroker();
    await setup.broker.request(PR_COMMENT_METHOD, prRequest({ dry_run: false }), CALLER);
    const reply = await setup.broker.request(
      REVIEW_THREAD_REPLY_METHOD,
      replyRequest({ dry_run: false }),
      CALLER,
    );
    expect(reply.posted).toBe(true);
    expect(setup.fake.posts()).toHaveLength(2);
    setup.broker.close();
  });

  test("serializes each comment target and rate-limits it across authorized callers", async () => {
    const cases = [
      {
        capability: PR_COMMENT_METHOD,
        first: prRequest({ dry_run: false }),
        second: prRequest({
          dry_run: false,
          client_idempotency_key: "second-caller-pr-0001",
        }),
      },
      {
        capability: REVIEW_THREAD_REPLY_METHOD,
        first: replyRequest({ dry_run: false }),
        second: replyRequest({
          dry_run: false,
          client_idempotency_key: "second-caller-reply-0001",
        }),
      },
    ] as const;
    for (const testCase of cases) {
      const setup = makeBroker();
      const results = await Promise.allSettled([
        setup.broker.request(testCase.capability, testCase.first, CALLER),
        setup.broker.request(testCase.capability, testCase.second, SECOND_CALLER),
      ]);
      expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
      expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
      expect(setup.fake.posts()).toHaveLength(1);
      await expect(
        setup.broker.request(testCase.capability, testCase.second, SECOND_CALLER),
      ).rejects.toThrow(/rate-limited/);
      setup.broker.close();
      rmSync(dir, { recursive: true, force: true });
      dir = mkdtempSync(join(tmpdir(), "github-comment-capabilities-"));
    }
  });

  test("an ambiguous target blocks every other authorized caller", async () => {
    const cases = [
      {
        capability: PR_COMMENT_METHOD,
        first: prRequest({ dry_run: false }),
        second: prRequest({
          dry_run: false,
          client_idempotency_key: "second-ambiguous-pr-0001",
        }),
      },
      {
        capability: REVIEW_THREAD_REPLY_METHOD,
        first: replyRequest({ dry_run: false }),
        second: replyRequest({
          dry_run: false,
          client_idempotency_key: "second-ambiguous-reply-0001",
        }),
      },
    ] as const;
    for (const testCase of cases) {
      const setup = makeBroker(fakeGithub({ postThrows: true }));
      await expect(
        setup.broker.request(testCase.capability, testCase.first, CALLER),
      ).rejects.toThrow(/ambiguous/);
      await expect(
        setup.broker.request(testCase.capability, testCase.second, SECOND_CALLER),
      ).rejects.toThrow(/ambiguous/);
      expect(setup.fake.posts()).toHaveLength(1);
      setup.broker.close();
      rmSync(dir, { recursive: true, force: true });
      dir = mkdtempSync(join(tmpdir(), "github-comment-capabilities-"));
    }
  });

  test("marks an ambiguous POST fail-closed and never retries it", async () => {
    const setup = makeBroker(fakeGithub({ postThrows: true }));
    const request = prRequest({ dry_run: false });
    await expect(setup.broker.request(PR_COMMENT_METHOD, request, CALLER)).rejects.toThrow(/ambiguous/);
    await expect(setup.broker.request(PR_COMMENT_METHOD, request, CALLER)).rejects.toThrow(
      /operator review/,
    );
    expect(setup.fake.posts()).toHaveLength(1);
    setup.broker.close();
  });

  test("fails closed on post-time PR drift and deleted-thread TOCTOU", async () => {
    const prSetup = makeBroker(fakeGithub({ driftAfterPost: true }));
    await expect(
      prSetup.broker.request(PR_COMMENT_METHOD, prRequest({ dry_run: false }), CALLER),
    ).rejects.toThrow(/head drifted|readback/);
    expect(prSetup.fake.posts()).toHaveLength(1);
    prSetup.broker.close();
    rmSync(dir, { recursive: true, force: true });
    dir = mkdtempSync(join(tmpdir(), "github-comment-capabilities-"));

    const threadSetup = makeBroker(fakeGithub({ anchorDeletedAfterPost: true }));
    await expect(
      threadSetup.broker.request(
        REVIEW_THREAD_REPLY_METHOD,
        replyRequest({ dry_run: false }),
        CALLER,
      ),
    ).rejects.toThrow(/GitHub API request failed/);
    expect(threadSetup.fake.posts()).toHaveLength(1);
    await expect(
      threadSetup.broker.request(
        REVIEW_THREAD_REPLY_METHOD,
        replyRequest({ dry_run: false }),
        CALLER,
      ),
    ).rejects.toThrow(/operator review/);
    threadSetup.broker.close();
  });

  test("fails closed when readback author, body, or reply anchor differs", async () => {
    for (const options of [
      { readbackLogin: "attacker" },
      { readbackBody: "changed" },
      { replyAnchorId: 6999 },
    ]) {
      const setup = makeBroker(fakeGithub(options));
      const capability = options.replyAnchorId ? REVIEW_THREAD_REPLY_METHOD : PR_COMMENT_METHOD;
      const request = options.replyAnchorId
        ? replyRequest({ dry_run: false })
        : prRequest({ dry_run: false });
      await expect(setup.broker.request(capability, request, CALLER)).rejects.toThrow(/readback/);
      expect(setup.fake.posts()).toHaveLength(1);
      setup.broker.close();
      rmSync(dir, { recursive: true, force: true });
      dir = mkdtempSync(join(tmpdir(), "github-comment-capabilities-"));
    }
  });

  test("persists processing crash state and requires operator reconciliation", async () => {
    const setup = makeBroker();
    setup.broker.close();
    const request = prRequest({ dry_run: false });
    const requestKey = createHash("sha256")
      .update(`${PR_COMMENT_METHOD}\0${CALLER.source}\0${request.client_idempotency_key}`)
      .digest("hex");
    const hash = createHash("sha256")
      .update(JSON.stringify({ capability: PR_COMMENT_METHOD, ...request, dry_run: false }))
      .digest("hex");
    const db = new Database(setup.stateFile);
    db.query(
      `INSERT INTO github_comment_requests
       (request_key, capability, caller, client_idempotency_key, payload_hash, rate_scope,
        repo, pr_number, head_sha, status, requested_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'processing', ?)`,
    ).run(
      requestKey,
      PR_COMMENT_METHOD,
      CALLER.source,
      request.client_idempotency_key,
      hash,
      `${REPO}\0${42}`,
      REPO,
      42,
      HEAD_A,
      1_700_000_000_000,
    );
    db.close();

    const recovered = makeBroker(setup.fake);
    await expect(
      recovered.broker.request(PR_COMMENT_METHOD, request, CALLER),
    ).rejects.toThrow(/operator review/);
    expect(recovered.fake.calls).toHaveLength(0);
    recovered.broker.close();
  });

  test("hash-only audit omits comment text and full policy redacts rejected secrets", async () => {
    const phrase = "unique private audit phrase ✅";
    const hashSetup = makeBroker();
    await hashSetup.broker.request(PR_COMMENT_METHOD, prRequest({ text: phrase }), CALLER);
    const hashAudit = readFileSync(hashSetup.auditFile, "utf8");
    expect(hashAudit).not.toContain(phrase);
    expect(hashAudit).toContain(createHash("sha256").update(phrase).digest("hex"));
    hashSetup.broker.close();
    rmSync(dir, { recursive: true, force: true });
    dir = mkdtempSync(join(tmpdir(), "github-comment-capabilities-"));

    const fullSetup = makeBroker(undefined, { auditTextPolicy: "redacted_full" });
    const secret = `github_pat_${"z".repeat(30)}`;
    await expect(
      fullSetup.broker.request(PR_COMMENT_METHOD, prRequest({ text: `leak ${secret}` }), CALLER),
    ).rejects.toThrow(/credential/);
    const fullAudit = readFileSync(fullSetup.auditFile, "utf8");
    expect(fullAudit).toContain("[REDACTED]");
    expect(fullAudit).not.toContain(secret);
    fullSetup.broker.close();
  });
});
