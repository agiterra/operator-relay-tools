#!/usr/bin/env bun
/** Credential-free MCP client for the owner-only CodeRabbit review broker. */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import {
  WireConnection,
  RpcClient,
  importPrivateKey,
  derivePublicKeyB64,
} from "@agiterra/wire-tools";
import { CODERABBIT_REVIEW_METHOD } from "./coderabbit-review.js";
import {
  PR_COMMENT_METHOD,
  REVIEW_THREAD_REPLY_METHOD,
} from "./github-comment-capabilities.js";

const FULL_REVIEW_TOOL = "request_coderabbit_full_review";
const PR_COMMENT_TOOL = "github_pr_comment";
const REVIEW_THREAD_REPLY_TOOL = "github_review_thread_reply";

const AUDIT_METADATA_SCHEMA = {
  type: "object" as const,
  additionalProperties: false,
  properties: {
    tracking_ref: {
      type: "string",
      minLength: 1,
      maxLength: 128,
      pattern: "^[A-Za-z0-9][A-Za-z0-9._:/#-]{0,127}$",
    },
    reason_code: {
      type: "string",
      enum: ["review_response", "operator_request", "incident_response", "other"],
    },
  },
  required: ["tracking_ref", "reason_code"],
};

const COMMENT_PROPERTIES = {
  repo: {
    type: "string",
    maxLength: 113,
    pattern: "^fabrica-land/[a-z0-9][a-z0-9._-]{0,99}$",
  },
  pr_number: { type: "integer", minimum: 1 },
  expected_head_sha: { type: "string", pattern: "^[0-9a-f]{40}$" },
  text: {
    type: "string",
    minLength: 1,
    maxLength: 8192,
    description: "Exact UTF-8 comment body. The broker enforces an 8192-byte limit and secret checks.",
  },
  dry_run: { type: "boolean" },
  client_idempotency_key: {
    type: "string",
    minLength: 16,
    maxLength: 128,
    pattern: "^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$",
  },
  justification: { type: "string", minLength: 1, maxLength: 1024 },
  audit_metadata: AUDIT_METADATA_SCHEMA,
};

const COMMENT_REQUIRED = [
  "repo",
  "pr_number",
  "expected_head_sha",
  "text",
  "dry_run",
  "client_idempotency_key",
  "justification",
  "audit_metadata",
];

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

async function main(): Promise<void> {
  const agentId = required("AGENT_ID");
  const brokerAgentId = required("CODERABBIT_REVIEW_BROKER_AGENT_ID");
  const wireUrl = process.env.WIRE_URL?.trim() || "http://127.0.0.1:9800";
  const privateKey = await importPrivateKey(required("AGENT_PRIVATE_KEY"));
  const publicKey = await derivePublicKeyB64(privateKey);
  const rpc = new RpcClient({
    url: wireUrl,
    agentId,
    signingKey: privateKey,
    defaultTimeoutMs: 30_000,
  });
  const connection = new WireConnection({
    url: wireUrl,
    agentId,
    agentName: agentId,
    keyPair: { privateKey, publicKey },
    deliver: async ({ raw }) => {
      rpc.handleEvent(raw);
    },
    onError: (error) =>
      console.error(
        "[coderabbit-review-mcp] Wire error",
        error instanceof Error ? error.message : String(error),
      ),
  });
  await connection.start();

  const mcp = new Server(
    { name: "coderabbit-review-request", version: "0.1.0" },
    {
      capabilities: { tools: {} },
      instructions:
        "Credential-free GitHub comment requests through an owner-only broker. " +
        "The fixed CodeRabbit command and each higher-privilege arbitrary-comment capability " +
        "have separate broker-side caller grants; listing a tool does not grant authority.",
    },
  );
  mcp.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: FULL_REVIEW_TOOL,
        description:
          "Ask the owner-only broker to post the fixed '@coderabbitai full review' command on an allowlisted open Fabrica PR. " +
          "The expected head SHA is mandatory; use dry_run first. No arbitrary comment text is accepted.",
        inputSchema: {
          type: "object" as const,
          additionalProperties: false,
          properties: {
            repo: {
              type: "string",
              maxLength: 113,
              pattern: "^fabrica-land/[a-z0-9][a-z0-9._-]{0,99}$",
            },
            pr_number: { type: "integer", minimum: 1 },
            review_mode: { type: "string", enum: ["full"] },
            expected_head_sha: { type: "string", pattern: "^[0-9a-f]{40}$" },
            dry_run: { type: "boolean", default: true },
          },
          required: ["repo", "pr_number", "review_mode", "expected_head_sha", "dry_run"],
        },
      },
      {
        name: PR_COMMENT_TOOL,
        description:
          "Request an exact PR-level comment as mividtim. Requires a separate github.pr_comment caller grant, expected head, idempotency key, and audit justification. Use dry_run first.",
        inputSchema: {
          type: "object" as const,
          additionalProperties: false,
          properties: COMMENT_PROPERTIES,
          required: COMMENT_REQUIRED,
        },
      },
      {
        name: REVIEW_THREAD_REPLY_TOOL,
        description:
          "Reply to the exact root review-comment anchor of a current-head PR thread as mividtim. Requires a separate github.review_thread_reply caller grant and dry-run first.",
        inputSchema: {
          type: "object" as const,
          additionalProperties: false,
          properties: {
            ...COMMENT_PROPERTIES,
            review_comment_id: { type: "integer", minimum: 1 },
          },
          required: [...COMMENT_REQUIRED, "review_comment_id"],
        },
      },
    ],
  }));
  mcp.setRequestHandler(CallToolRequestSchema, async (request) => {
    const methods: Record<string, string> = {
      [FULL_REVIEW_TOOL]: CODERABBIT_REVIEW_METHOD,
      [PR_COMMENT_TOOL]: PR_COMMENT_METHOD,
      [REVIEW_THREAD_REPLY_TOOL]: REVIEW_THREAD_REPLY_METHOD,
    };
    const method = methods[request.params.name];
    if (!method) {
      return { content: [{ type: "text", text: "Unknown tool" }], isError: true };
    }
    try {
      const result = await rpc.request(
        brokerAgentId,
        method,
        request.params.arguments ?? {},
      );
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    } catch (error) {
      return {
        content: [{ type: "text", text: error instanceof Error ? error.message : String(error) }],
        isError: true,
      };
    }
  });

  const stop = async () => {
    await connection.stop();
  };
  process.once("SIGINT", () => void stop());
  process.once("SIGTERM", () => void stop());
  await mcp.connect(new StdioServerTransport());
}

main().catch((error) => {
  console.error("[coderabbit-review-mcp] fatal", error instanceof Error ? error.message : String(error));
  process.exit(1);
});
