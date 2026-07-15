import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { createHash } from "node:crypto";
import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  CODERABBIT_FULL_REVIEW_COMMENT,
  CoderabbitReviewBroker,
  type CoderabbitReviewRequest,
} from "./coderabbit-review.js";
import { FineGrainedPatFileTokenSource } from "./github-token-source.js";

const HEAD_A = "a".repeat(40);
const HEAD_B = "b".repeat(40);
const REPO = "fabrica-land/fabrica-v3-api";
const CALLER = { source: "brioche", sourcePubkey: "verified-public-key-0001" };

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "coderabbit-review-broker-"));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

type FakeOptions = {
  login?: string;
  repo?: string;
  state?: string;
  currentHead?: string;
  readbackBody?: string;
  readbackLogin?: string;
  driftAfterPost?: boolean;
  postThrows?: boolean;
};

function fakeGithub(options: FakeOptions = {}) {
  let posted = false;
  const calls: Array<{ url: string; method: string; auth: string | null; body?: unknown }> = [];
  let head = options.currentHead ?? HEAD_A;
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
      const returnedHead = posted && options.driftAfterPost ? HEAD_B : head;
      return Response.json({
        number: 42,
        state: options.state ?? "open",
        head: { sha: returnedHead },
        base: { repo: { full_name: options.repo ?? REPO } },
      });
    }
    if (url.endsWith("/issues/42/comments") && method === "POST") {
      posted = true;
      if (options.postThrows) throw new Error("simulated ambiguous transport failure");
      return Response.json({
        id: 9001,
        body: CODERABBIT_FULL_REVIEW_COMMENT,
        html_url: "https://github.com/fabrica-land/fabrica-v3-api/pull/42#issuecomment-9001",
        user: { login: "mividtim" },
      });
    }
    if (url.endsWith("/issues/comments/9001")) {
      return Response.json({
        id: 9001,
        body: options.readbackBody ?? CODERABBIT_FULL_REVIEW_COMMENT,
        html_url: "https://github.com/fabrica-land/fabrica-v3-api/pull/42#issuecomment-9001",
        user: { login: options.readbackLogin ?? "mividtim" },
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

function request(overrides: Partial<CoderabbitReviewRequest> = {}): CoderabbitReviewRequest {
  return {
    repo: REPO,
    pr_number: 42,
    review_mode: "full",
    expected_head_sha: HEAD_A,
    dry_run: true,
    ...overrides,
  };
}

function makeBroker(fake = fakeGithub(), token = "github_pat_owner-secret-token", minimumIntervalMs = 60_000) {
  const tokenFile = join(dir, "github-token");
  const stateFile = join(dir, "state", "requests.sqlite");
  const auditFile = join(dir, "audit", "requests.jsonl");
  writeFileSync(tokenFile, `${token}\n`, { mode: 0o600 });
  chmodSync(tokenFile, 0o600);
  let now = 1_700_000_000_000;
  const broker = new CoderabbitReviewBroker({
    allowedRepos: new Set([REPO, "fabrica-land/soil-app"]),
    allowedCallers: new Map([
      ["brioche", new Set([CALLER.sourcePubkey])],
      ["vacherin", new Set(["vacherin-public-key-0001"])],
    ]),
    tokenSource: new FineGrainedPatFileTokenSource(tokenFile),
    stateFile,
    auditFile,
    minimumIntervalMs,
    fetchImpl: fake.fetchImpl,
    now: () => now,
  });
  return {
    broker,
    fake,
    tokenFile,
    stateFile,
    auditFile,
    advance: (ms: number) => { now += ms; },
  };
}

describe("CoderabbitReviewBroker", () => {
  test("dry-run validates identity, target, and head without posting", async () => {
    const { broker, fake } = makeBroker();
    const result = await broker.request(request(), CALLER);
    expect(result.dry_run).toBe(true);
    expect(result.would_post).toBe(true);
    expect(fake.posts()).toHaveLength(0);
    broker.close();
  });

  test("posts only the fixed command and verifies readback identity", async () => {
    const { broker, fake } = makeBroker();
    const result = await broker.request(request({ dry_run: false }), CALLER);
    expect(result.posted).toBe(true);
    expect(result.github_login).toBe("mividtim");
    expect(fake.posts()).toHaveLength(1);
    expect(fake.posts()[0]!.body).toEqual({ body: CODERABBIT_FULL_REVIEW_COMMENT });
    broker.close();
  });

  test("is idempotent for repo, PR, head, and mode", async () => {
    const { broker, fake } = makeBroker();
    await broker.request(request({ dry_run: false }), CALLER);
    const duplicate = await broker.request(request({ dry_run: false }), CALLER);
    expect(duplicate.idempotent).toBe(true);
    expect(duplicate.comment_id).toBe(9001);
    expect(fake.posts()).toHaveLength(1);
    broker.close();
  });

  test("serializes concurrent identical requests into one post", async () => {
    const { broker, fake } = makeBroker();
    const results = await Promise.allSettled([
      broker.request(request({ dry_run: false }), CALLER),
      broker.request(request({ dry_run: false }), CALLER),
    ]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
    const rejected = results.find((result) => result.status === "rejected") as PromiseRejectedResult;
    expect(String(rejected.reason)).toMatch(/in progress|ambiguous/);
    expect(fake.posts()).toHaveLength(1);
    const duplicate = await broker.request(request({ dry_run: false }), CALLER);
    expect(duplicate.idempotent).toBe(true);
    expect(fake.posts()).toHaveLength(1);
    broker.close();
  });

  test("serializes distinct-head races and enforces the same-PR rate limit", async () => {
    const setup = makeBroker();
    const results = await Promise.allSettled([
      setup.broker.request(request({ dry_run: false }), CALLER),
      setup.broker.request(
        request({ expected_head_sha: HEAD_B, dry_run: false }),
        CALLER,
      ),
    ]);
    expect(results[0]!.status).toBe("fulfilled");
    expect(results[1]!.status).toBe("rejected");
    expect(String((results[1] as PromiseRejectedResult).reason)).toMatch(/in progress|ambiguous/);
    expect(setup.fake.posts()).toHaveLength(1);

    setup.fake.setHead(HEAD_B);
    await expect(
      setup.broker.request(request({ expected_head_sha: HEAD_B, dry_run: false }), CALLER),
    ).rejects.toThrow(/rate-limited/);
    expect(setup.fake.posts()).toHaveLength(1);
    setup.broker.close();
  });

  test("rejects missing broker-verified public key", async () => {
    const { broker, fake } = makeBroker();
    await expect(broker.request(request(), { source: "brioche" })).rejects.toThrow(/not authorized/);
    expect(fake.calls).toHaveLength(0);
    broker.close();
  });

  test("rejects caller id/public-key mismatch, including optional Vacherin", async () => {
    const { broker, fake, auditFile } = makeBroker();
    await expect(
      broker.request(request(), { source: "vacherin", sourcePubkey: CALLER.sourcePubkey }),
    ).rejects.toThrow(/not authorized/);
    expect(fake.calls).toHaveLength(0);
    const audit = readFileSync(auditFile, "utf8");
    expect(audit).toContain('"caller":"vacherin"');
    expect(audit).toContain('"outcome":"refused_or_failed"');
    expect(audit).not.toContain(CALLER.sourcePubkey);
    broker.close();
  });

  test("rejects arbitrary comment text and all additional properties", async () => {
    const { broker, fake } = makeBroker();
    await expect(
      broker.request({ ...request(), comment: "@someone destructive" }, CALLER),
    ).rejects.toThrow(/unexpected request property/);
    expect(fake.calls).toHaveLength(0);
    broker.close();
  });

  test("internal request initialization cannot override the broker Authorization header", async () => {
    const setup = makeBroker();
    const hidden = setup.broker as unknown as {
      githubJson<T>(token: string, path: string, init?: RequestInit): Promise<T>;
    };
    await hidden.githubJson("github_pat_owner-secret-token", "/user", {
      headers: { Authorization: "Bearer attacker-controlled" },
    });
    expect(setup.fake.calls[0]!.auth).toBe("Bearer github_pat_owner-secret-token");
    setup.broker.close();
  });

  test("rejects SSRF, repo spoofing, traversal, Unicode, and injection targets", async () => {
    const { broker, fake } = makeBroker();
    const attacks = [
      "https://evil.invalid/fabrica-land/fabrica-v3-api",
      "fabrica-land/fabrica-v3-api/../../evil",
      "fabrica-land/fabrica-v3-api@evil.invalid",
      "evil/fabrica-v3-api",
      "fabrica-land/FABRICA-V3-API",
      "fabrica-land/fabrica-v3-api%2Fevil",
      "fabrica-land/fabrica-v3-api\nX-Injected: yes",
      "fabrica‐land/fabrica-v3-api",
    ];
    for (const repo of attacks) {
      await expect(broker.request(request({ repo }), CALLER)).rejects.toThrow();
    }
    expect(fake.calls).toHaveLength(0);
    broker.close();
  });

  test("fails closed when GitHub returns a spoofed repository", async () => {
    const fake = fakeGithub({ repo: "fabrica-land/other" });
    const { broker } = makeBroker(fake);
    await expect(broker.request(request(), CALLER)).rejects.toThrow(/target identity drifted/);
    expect(fake.posts()).toHaveLength(0);
    broker.close();
  });

  test("fails closed for a closed PR", async () => {
    const fake = fakeGithub({ state: "closed" });
    const { broker } = makeBroker(fake);
    await expect(broker.request(request(), CALLER)).rejects.toThrow(/not open/);
    expect(fake.posts()).toHaveLength(0);
    broker.close();
  });

  test("fails closed when the PR head does not match", async () => {
    const fake = fakeGithub({ currentHead: HEAD_B });
    const { broker } = makeBroker(fake);
    await expect(broker.request(request(), CALLER)).rejects.toThrow(/head drifted/);
    expect(fake.posts()).toHaveLength(0);
    broker.close();
  });

  test("fails closed when the credential is not mividtim", async () => {
    const fake = fakeGithub({ login: "some-app[bot]" });
    const { broker } = makeBroker(fake);
    await expect(broker.request(request(), CALLER)).rejects.toThrow(/identity drifted/);
    expect(fake.posts()).toHaveLength(0);
    broker.close();
  });

  test("rejects group/world-readable credential files", async () => {
    const setup = makeBroker();
    chmodSync(setup.tokenFile, 0o644);
    await expect(setup.broker.request(request(), CALLER)).rejects.toThrow(/owner-only|private/);
    expect(setup.fake.calls).toHaveLength(0);
    setup.broker.close();
  });

  test("reads the token file per request so atomic rotation needs no agent change", async () => {
    const setup = makeBroker();
    await setup.broker.request(request(), CALLER);
    writeFileSync(setup.tokenFile, "github_pat_rotated-owner-token\n", { mode: 0o600 });
    chmodSync(setup.tokenFile, 0o600);
    await setup.broker.request(request(), CALLER);
    const userCalls = setup.fake.calls.filter((call) => call.url.endsWith("/user"));
    expect(userCalls[0]!.auth).toBe("Bearer github_pat_owner-secret-token");
    expect(userCalls[1]!.auth).toBe("Bearer github_pat_rotated-owner-token");
    setup.broker.close();
  });

  test("rate-limits a second head on the same PR", async () => {
    const setup = makeBroker();
    await setup.broker.request(request({ dry_run: false }), CALLER);
    setup.fake.setHead(HEAD_B);
    await expect(
      setup.broker.request(request({ expected_head_sha: HEAD_B, dry_run: false }), CALLER),
    ).rejects.toThrow(/rate-limited/);
    expect(setup.fake.posts()).toHaveLength(1);
    setup.broker.close();
  });

  test("allows another head after the configured rate interval", async () => {
    const setup = makeBroker(undefined, undefined, 1_000);
    await setup.broker.request(request({ dry_run: false }), CALLER);
    setup.advance(1_001);
    setup.fake.setHead(HEAD_B);
    const result = await setup.broker.request(
      request({ expected_head_sha: HEAD_B, dry_run: false }),
      CALLER,
    );
    expect(result.posted).toBe(true);
    expect(setup.fake.posts()).toHaveLength(2);
    setup.broker.close();
  });

  test("marks readback author mismatch unsafe and never retries the post", async () => {
    const fake = fakeGithub({ readbackLogin: "some-app[bot]" });
    const setup = makeBroker(fake);
    await expect(setup.broker.request(request({ dry_run: false }), CALLER)).rejects.toThrow(/readback/);
    await expect(setup.broker.request(request({ dry_run: false }), CALLER)).rejects.toThrow(/operator review/);
    expect(fake.posts()).toHaveLength(1);
    setup.broker.close();
  });

  test("marks post-time head drift unsafe and never retries", async () => {
    const fake = fakeGithub({ driftAfterPost: true });
    const setup = makeBroker(fake);
    await expect(setup.broker.request(request({ dry_run: false }), CALLER)).rejects.toThrow(/during comment/);
    await expect(setup.broker.request(request({ dry_run: false }), CALLER)).rejects.toThrow(/operator review/);
    expect(fake.posts()).toHaveLength(1);
    setup.broker.close();
  });

  test("never retries after an ambiguous comment transport failure", async () => {
    const fake = fakeGithub({ postThrows: true });
    const setup = makeBroker(fake);
    await expect(setup.broker.request(request({ dry_run: false }), CALLER)).rejects.toThrow(
      /ambiguous transport/,
    );
    await expect(setup.broker.request(request({ dry_run: false }), CALLER)).rejects.toThrow(
      /operator review/,
    );
    expect(fake.posts()).toHaveLength(1);
    setup.broker.close();
  });

  test("crash recovery keeps persisted processing state fail-closed", async () => {
    const setup = makeBroker();
    setup.broker.close();
    const key = createHash("sha256")
      .update(`${REPO}\0${42}\0${HEAD_A}\0full`)
      .digest("hex");
    const db = new Database(setup.stateFile);
    db.query(
      `INSERT INTO review_requests
       (request_key, repo, pr_number, head_sha, review_mode, caller, status, requested_at)
       VALUES (?, ?, ?, ?, 'full', ?, 'processing', ?)`,
    ).run(key, REPO, 42, HEAD_A, CALLER.source, 1_700_000_000_000);
    db.close();

    const recovered = new CoderabbitReviewBroker({
      allowedRepos: new Set([REPO]),
      allowedCallers: new Map([[CALLER.source, new Set([CALLER.sourcePubkey])]]),
      tokenSource: new FineGrainedPatFileTokenSource(setup.tokenFile),
      stateFile: setup.stateFile,
      auditFile: setup.auditFile,
      minimumIntervalMs: 60_000,
      fetchImpl: setup.fake.fetchImpl,
      now: () => 1_700_000_100_000,
    });
    await expect(recovered.request(request({ dry_run: false }), CALLER)).rejects.toThrow(
      /ambiguous prior outcome|operator review/,
    );
    expect(setup.fake.calls).toHaveLength(0);
    recovered.close();

    const readback = new Database(setup.stateFile, { readonly: true });
    const row = readback
      .query<{ status: string }, [string]>(
        "SELECT status FROM review_requests WHERE request_key = ?",
      )
      .get(key);
    expect(row?.status).toBe("processing");
    readback.close();
  });

  test("audit/state are owner-only and audit never contains the credential", async () => {
    const setup = makeBroker();
    await setup.broker.request(request(), CALLER);
    expect(statSync(setup.auditFile).mode & 0o077).toBe(0);
    expect(statSync(setup.stateFile).mode & 0o077).toBe(0);
    expect(statSync(`${setup.stateFile}-wal`).mode & 0o077).toBe(0);
    expect(statSync(`${setup.stateFile}-shm`).mode & 0o077).toBe(0);
    const audit = readFileSync(setup.auditFile, "utf8");
    expect(audit).not.toContain("github_pat_owner-secret-token");
    expect(audit).toContain('"outcome":"dry_run"');
    setup.broker.close();
  });
});
