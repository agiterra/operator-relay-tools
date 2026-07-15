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
import { githubTokenSourceFromEnv } from "./github-token-source.js";

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
  const broker = new CoderabbitReviewBroker({
    allowedRepos: parseAllowedRepos(required("CODERABBIT_BROKER_ALLOWED_REPOS")),
    allowedCallers: parseAllowedCallers(required("CODERABBIT_BROKER_ALLOWED_CALLERS_JSON")),
    tokenSource: githubTokenSourceFromEnv(),
    stateFile: required("CODERABBIT_BROKER_STATE_FILE"),
    auditFile: required("CODERABBIT_BROKER_AUDIT_FILE"),
    minimumIntervalMs: Number(process.env.CODERABBIT_BROKER_MINIMUM_INTERVAL_MS ?? 30 * 60_000),
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
    },
    // Wire supplies source_pubkey only for broker-verified frames. Authorization
    // remains inside broker.request so every denied attempt reaches the
    // owner-only audit log instead of disappearing at the RPC dispatch layer.
    log: (message, error) => {
      // Never log params, headers, request bodies, env, or credential values.
      console.error(`[coderabbit-review-broker] ${message}`, error instanceof Error ? error.message : "");
    },
  });

  const connection = new WireConnection({
    url: wireUrl,
    agentId,
    agentName: agentId,
    keyPair: { privateKey, publicKey },
    deliver: async ({ raw }) => {
      if (await responder.handleEvent(raw)) return;
      console.error(`[coderabbit-review-broker] ignored topic '${raw.topic}' from '${raw.source}'`);
    },
    onConnect: () => console.error(`[coderabbit-review-broker] connected as ${agentId}`),
    onDisconnect: () => console.error("[coderabbit-review-broker] disconnected"),
    onError: (error) =>
      console.error(
        "[coderabbit-review-broker] Wire error",
        error instanceof Error ? error.message : String(error),
      ),
  });

  const stop = async () => {
    await connection.stop();
    broker.close();
    process.exit(0);
  };
  process.once("SIGINT", () => void stop());
  process.once("SIGTERM", () => void stop());
  await connection.start();
}

main().catch((error) => {
  console.error("[coderabbit-review-broker] fatal", error instanceof Error ? error.message : String(error));
  process.exit(1);
});
