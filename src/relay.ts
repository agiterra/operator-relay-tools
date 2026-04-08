/**
 * Operator-prompt relay.
 *
 * Forwards operator prompts from ephemeral agents to their managing agent
 * via Wire IPC. The managing agent gets visibility into what the operator
 * told its ephemerals.
 *
 * State is a simple JSON file at ~/.wire/operator-relay.json:
 * { "agentId": { "notify": "brioche", "privateKeyB64": "..." } }
 */

import { join } from "path";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "fs";

const STATE_FILE = join(process.env.HOME ?? "/tmp", ".wire", "operator-relay.json");

export interface RelayConfig {
  notify: string;
}

interface RelayState {
  [agentId: string]: RelayConfig;
}

function loadState(): RelayState {
  if (!existsSync(STATE_FILE)) return {};
  try {
    return JSON.parse(readFileSync(STATE_FILE, "utf-8"));
  } catch {
    return {};
  }
}

function saveState(state: RelayState): void {
  const dir = join(process.env.HOME ?? "/tmp", ".wire");
  mkdirSync(dir, { recursive: true });
  writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
}

/** Register an agent for operator-prompt relay. */
export function startRelay(agentId: string, notify: string): void {
  const state = loadState();
  state[agentId] = { notify };
  saveState(state);
}

/** Unregister an agent from operator-prompt relay. */
export function stopRelay(agentId: string): void {
  const state = loadState();
  delete state[agentId];
  saveState(state);
}

/** Get relay config for an agent, or null if not registered. */
export function getRelay(agentId: string): RelayConfig | null {
  const state = loadState();
  return state[agentId] ?? null;
}

/** List all active relays. */
export function listRelays(): RelayState {
  return loadState();
}

/**
 * Forward an operator prompt to the managing agent.
 * Uses the Wire gateway to deliver via IPC.
 */
export async function forwardPrompt(opts: {
  agentId: string;
  notify: string;
  prompt: string;
  wireUrl?: string;
}): Promise<void> {
  const wireUrl = opts.wireUrl ?? process.env.WIRE_URL ?? "http://localhost:9800";

  const payload = {
    type: "operator-prompt",
    agent: opts.agentId,
    content: opts.prompt,
    timestamp: new Date().toISOString(),
  };

  // Send unsigned (relay is infrastructure, not agent-to-agent conversation)
  const response = await fetch(`${wireUrl}/publish`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      source: opts.agentId,
      topic: "operator-relay",
      dest: opts.notify,
      payload,
    }),
  });

  if (!response.ok) {
    throw new Error(`relay failed: ${response.status} ${await response.text()}`);
  }
}
