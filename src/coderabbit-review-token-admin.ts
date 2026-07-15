#!/usr/bin/env bun
/** Owner-only token administration. Never expose this command through agent MCP. */

import {
  GithubAppUserTokenSource,
  githubTokenSourceFromEnv,
} from "./github-token-source.js";

async function main(): Promise<void> {
  process.umask(0o077);
  const [command, confirmation, ...extra] = process.argv.slice(2);
  if (
    command !== "revoke-github-app-user" ||
    confirmation !== "--confirm-revoke-all-user-grants" ||
    extra.length > 0
  ) {
    throw new Error(
      "usage: coderabbit-review-token-admin revoke-github-app-user --confirm-revoke-all-user-grants",
    );
  }
  const source = githubTokenSourceFromEnv();
  if (!(source instanceof GithubAppUserTokenSource)) {
    throw new Error("revocation command requires CODERABBIT_BROKER_TOKEN_SOURCE=github_app_user");
  }
  await source.revokeAuthorization();
  console.error("GitHub App user authorization revoked; local user-token state removed");
}

main().catch((error) => {
  console.error(
    "[coderabbit-review-token-admin] failed",
    error instanceof Error ? error.message : String(error),
  );
  process.exit(1);
});
