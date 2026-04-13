#!/usr/bin/env bun
/**
 * Operator-relay MCP server — runtime-agnostic adapter.
 *
 * Exposes tools for managing operator-prompt relays on ephemeral agents.
 * The managing agent (e.g. Brioche) calls operator_relay_start after
 * spawning an ephemeral to get notifications when the operator prompts it.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { startRelay, stopRelay, listRelays } from "./index.js";

const mcp = new Server(
  { name: "operator-relay", version: "0.1.0" },
  {
    capabilities: { tools: {} },
    instructions:
      "Operator-prompt relay. When the operator (Tim) prompts an ephemeral agent, " +
      "the managing agent receives a Wire notification with the full prompt content. " +
      "Use operator_relay_start after spawning an ephemeral to enable.",
  },
);

mcp.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "operator_relay_start",
      description:
        "Start relaying operator prompts from an ephemeral agent to you. " +
        "After calling this, any time the operator prompts the ephemeral, " +
        "you'll receive a Wire notification with the full prompt content.",
      inputSchema: {
        type: "object" as const,
        properties: {
          agent: {
            type: "string",
            description: "Agent ID to relay prompts from",
          },
          notify: {
            type: "string",
            description: "Agent ID to notify (your ID). Defaults to AGENT_ID.",
          },
        },
        required: ["agent"],
      },
    },
    {
      name: "operator_relay_stop",
      description: "Stop relaying operator prompts from an agent.",
      inputSchema: {
        type: "object" as const,
        properties: {
          agent: {
            type: "string",
            description: "Agent ID to stop relaying from",
          },
        },
        required: ["agent"],
      },
    },
    {
      name: "operator_relay_list",
      description: "List all active operator-prompt relays.",
      inputSchema: {
        type: "object" as const,
        properties: {},
      },
    },
  ],
}));

mcp.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: a = {} } = req.params;

  switch (name) {
    case "operator_relay_start": {
      const agent = a.agent as string;
      const notify =
        (a.notify as string) ??
        process.env.AGENT_ID;
      if (!notify) {
        return {
          content: [
            { type: "text", text: "Error: no notify agent ID — set AGENT_ID or pass notify param" },
          ],
        };
      }
      try {
        startRelay(agent, notify);
      } catch (e: any) {
        return {
          content: [{ type: "text", text: `Error: ${e.message}` }],
          isError: true,
        };
      }
      return {
        content: [
          {
            type: "text",
            text: `Relay started: operator prompts to '${agent}' will be forwarded to '${notify}' via Wire topic 'operator-relay'.`,
          },
        ],
      };
    }

    case "operator_relay_stop": {
      const agent = a.agent as string;
      stopRelay(agent);
      return {
        content: [
          { type: "text", text: `Relay stopped for '${agent}'.` },
        ],
      };
    }

    case "operator_relay_list": {
      const relays = listRelays();
      const entries = Object.entries(relays);
      if (entries.length === 0) {
        return {
          content: [{ type: "text", text: "No active relays." }],
        };
      }
      const lines = entries.map(
        ([agent, cfg]) => `${agent} → ${cfg.notify}`,
      );
      return {
        content: [
          { type: "text", text: `Active relays:\n${lines.join("\n")}` },
        ],
      };
    }

    default:
      return {
        content: [{ type: "text", text: `Unknown tool: ${name}` }],
        isError: true,
      };
  }
});

export async function startServer(): Promise<void> {
  const transport = new StdioServerTransport();
  await mcp.connect(transport);
}
