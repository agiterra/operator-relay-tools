#!/usr/bin/env bun
/**
 * Owner-only CodeRabbit review broker.
 *
 * This process is a declared Wire server-plugin identity. Agents never see
 * the GitHub credential: they send a signed RPC request, while this broker
 * requires the broker-verified source_pubkey before performing any write.
 */

import {
  WireConnection,
  RpcResponder,
  importPrivateKey,
  derivePublicKeyB64,
} from "@agiterra/wire-tools";

import {
  CODERABBIT_REVIEW_METHOD,
  CoderabbitReviewBroker,
  parseAllowedCallers,
  parseAllowedRepos,
} from "./coderabbit-review.js";
import {
  GithubCommentCapabilitiesBroker,
  PR_COMMENT_METHOD,
  REVIEW_THREAD_REPLY_METHOD,
  parseCapabilityCallers,
} from "./github-comment-capabilities.js";
import { githubTokenSourceFromEnv } from "./github-token-source.js";

/**
 * ⛔⛔ EVERY LINE THIS PROCESS LOGGED WAS UNDATED, WHICH MADE THE LOG USELESS FOR THE ONE
 * JOB IT HAS (2026-08-11). Brioche reported CodeRabbit silent for ~14 hours; I read 274
 * non-keepalive lines here and could not tell last night's from July's. The most alarming
 * of them — `ignored topic 'webhook.github.coderabbit_full_review' from 'brioche'` — is
 * j:320's symptom VERBATIM from 2026-07-30, already fixed, and I nearly reported it as
 * current.
 * ⇒ An undated log does not merely lack detail: it CANNOT ANSWER "did this happen during
 *   the incident?", which is the only question anyone brings to it. Ordering is not a
 *   substitute, because keepalives dominate and `tail` spans an unknown period.
 * ⇒ Timestamps only. This changes WHEN is recorded and nothing about WHAT — the
 *   never-log-params-headers-bodies-env-or-credentials rule below is untouched.
 */
const stamp = () => new Date().toISOString();
const logLine = (...parts: unknown[]) => console.error(`${stamp()} [coderabbit-review-broker]`, ...parts);

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

async function main(): Promise<void> {
  process.umask(0o077);
  const agentId = required("AGENT_ID");
  if (!agentId.startsWith("github-review-broker@")) {
    throw new Error("AGENT_ID must be a dedicated github-review-broker@<machine> server-plugin identity");
  }
  const wireUrl = process.env.WIRE_URL?.trim() || "http://127.0.0.1:9800";
  const privateKey = await importPrivateKey(required("AGENT_PRIVATE_KEY"));
  const publicKey = await derivePublicKeyB64(privateKey);
  const allowedRepos = parseAllowedRepos(required("CODERABBIT_BROKER_ALLOWED_REPOS"));
  const tokenSource = githubTokenSourceFromEnv();
  const stateFile = required("CODERABBIT_BROKER_STATE_FILE");
  const auditFile = required("CODERABBIT_BROKER_AUDIT_FILE");
  const auditTextPolicy = process.env.GITHUB_COMMENT_BROKER_AUDIT_TEXT_POLICY?.trim() || "hash";
  if (auditTextPolicy !== "hash" && auditTextPolicy !== "redacted_full") {
    throw new Error(
      "GITHUB_COMMENT_BROKER_AUDIT_TEXT_POLICY must be exactly 'hash' or 'redacted_full'",
    );
  }
  const broker = new CoderabbitReviewBroker({
    allowedRepos,
    allowedCallers: parseAllowedCallers(required("CODERABBIT_BROKER_ALLOWED_CALLERS_JSON")),
    tokenSource,
    stateFile,
    auditFile,
    minimumIntervalMs: Number(process.env.CODERABBIT_BROKER_MINIMUM_INTERVAL_MS ?? 30 * 60_000),
  });
  const commentBroker = new GithubCommentCapabilitiesBroker({
    allowedRepos,
    allowedCapabilityCallers: parseCapabilityCallers(
      process.env.GITHUB_COMMENT_BROKER_ALLOWED_CALLERS_JSON ?? "{}",
    ),
    tokenSource,
    stateFile,
    auditFile,
    auditTextPolicy,
    prCommentMinimumIntervalMs: Number(
      process.env.GITHUB_COMMENT_BROKER_PR_COMMENT_MINIMUM_INTERVAL_MS ?? 60 * 60_000,
    ),
    reviewReplyMinimumIntervalMs: Number(
      process.env.GITHUB_COMMENT_BROKER_REVIEW_REPLY_MINIMUM_INTERVAL_MS ?? 30 * 60_000,
    ),
  });

  const responder = new RpcResponder({
    url: wireUrl,
    agentId,
    signingKey: privateKey,
    methods: {
      [CODERABBIT_REVIEW_METHOD]: (params, context) =>
        broker.request(params, {
          source: context.source,
          sourcePubkey: context.event.source_pubkey,
        }),
      [PR_COMMENT_METHOD]: (params, context) =>
        commentBroker.request(PR_COMMENT_METHOD, params, {
          source: context.source,
          sourcePubkey: context.event.source_pubkey,
        }),
      [REVIEW_THREAD_REPLY_METHOD]: (params, context) =>
        commentBroker.request(REVIEW_THREAD_REPLY_METHOD, params, {
          source: context.source,
          sourcePubkey: context.event.source_pubkey,
        }),
    },
    // Wire supplies source_pubkey only for broker-verified frames. Authorization
    // remains inside broker.request so every denied attempt reaches the
    // owner-only audit log instead of disappearing at the RPC dispatch layer.
    log: (message, error) => {
      // Never log params, headers, request bodies, env, or credential values.
      logLine(message, error instanceof Error ? error.message : "");
    },
  });

  const connection = new WireConnection({
    url: wireUrl,
    agentId,
    agentName: agentId,
    keyPair: { privateKey, publicKey },
    deliver: async ({ raw }) => {
      if (await responder.handleEvent(raw)) return;
      logLine(`ignored topic '${raw.topic}' from '${raw.source}'`);
    },
    onConnect: () => logLine(`connected as ${agentId}`),
    onDisconnect: () => logLine("disconnected"),
    onError: (error) =>
      logLine("Wire error", error instanceof Error ? error.message : String(error)),
  });

  const stop = async () => {
    await connection.stop();
    broker.close();
    commentBroker.close();
    process.exit(0);
  };
  process.once("SIGINT", () => void stop());
  process.once("SIGTERM", () => void stop());
  await connection.start();
}

main().catch((error) => {
  logLine("fatal", error instanceof Error ? error.message : String(error));
  process.exit(1);
});
