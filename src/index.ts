export {
  startRelay,
  stopRelay,
  getRelay,
  listRelays,
  forwardPrompt,
  type RelayConfig,
} from "./relay.js";

// MCP server (shared by claude-code and codex adapters)
export { startServer } from "./mcp-server.js";
