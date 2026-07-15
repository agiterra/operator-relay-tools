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

const TOOL_NAME = "request_coderabbit_full_review";

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
        "Requests the fixed CodeRabbit full-review command through an owner-only broker. " +
        "This client has no GitHub credential and cannot submit arbitrary comments.",
    },
  );
  mcp.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: TOOL_NAME,
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
    ],
  }));
  mcp.setRequestHandler(CallToolRequestSchema, async (request) => {
    if (request.params.name !== TOOL_NAME) {
      return { content: [{ type: "text", text: "Unknown tool" }], isError: true };
    }
    try {
      const result = await rpc.request(
        brokerAgentId,
        CODERABBIT_REVIEW_METHOD,
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
