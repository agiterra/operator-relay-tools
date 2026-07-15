# CodeRabbit full-review broker

Status: **implemented but disabled**. Do not install, enroll, allowlist, or use
this capability on a live pull request until independent security review and an
explicit operator release.

## Why this is a broker

An ordinary GitHub App installation token posts as the App bot, not as the
operator. The requested `mividtim` attribution therefore requires either:

1. a GitHub App user access token acting on behalf of `mividtim` (preferred
   when its OAuth/refresh lifecycle is available), or
2. a narrowly scoped fine-grained personal access token for `mividtim` with
   issue-comment write access only to the allowlisted Fabrica repositories.

Neither credential may enter an agent environment, MCP configuration, prompt,
Wire message, command line, log, or audit record. A token-source abstraction
keeps both options inside the owner-only runtime:

- `github_app_user` (preferred) reads an expiring user access/refresh-token
  state file and GitHub App client-secret file, refreshes through GitHub's
  fixed OAuth endpoint before expiry, atomically rotates both tokens, and
  never returns refresh material outside the source.
- `fine_grained_pat` (fallback) reads a repository-scoped PAT from an
  owner-only file for every request so rotation is immediate.

A per-agent `github-tools` MCP extension was rejected because that process
model would delegate the credential to every caller.

## Components

- `coderabbit-review-mcp`: credential-free agent MCP client. It accepts only
  `repo`, `pr_number`, `review_mode: "full"`, `expected_head_sha`, and
  `dry_run`. It sends a signed Wire RPC request.
- `coderabbit-review-broker`: dedicated permanent Wire server-plugin. It is the
  only process that can read the GitHub credential and call GitHub.
- `CoderabbitReviewBroker`: pure/injectable policy and GitHub implementation,
  covered by adversarial tests.

The broker RPC method is `github.coderabbit_full_review`. The only possible
comment body is:

```text
@coderabbitai full review
```

## Trust boundary

The broker identity must be declared in Wire's `server_plugins` configuration.
Wire then stamps `source_pubkey` only for locally JWT-verified ingress. The
broker requires both:

- exact caller agent ID, and
- exact broker-verified Ed25519 public key from an owner-controlled map.

Missing keys, federated frames, source spoofing, and caller/key mismatches fail
closed. Adding Vacherin is a configuration change: its current public key must
be added explicitly; naming the caller `vacherin` is insufficient.

## Threat model

The broker assumes an allowed agent may be buggy or malicious, GitHub or the
network may return an ambiguous result, and local non-owner processes may try
to inspect or replace files. It therefore defends against arbitrary-comment
injection, SSRF/repository spoofing, caller-ID spoofing, stale or stolen
caller keys, credential/target/head drift, duplicate/rate-abusive requests,
crash-after-POST retries, symlink/permission attacks, and leakage through
agent configuration, argv, logs, results, or audit. Compromise of the broker's
own OS identity is outside this boundary and requires immediate revocation.

## Request flow

1. Strict-schema validation rejects arbitrary comment text and unknown fields.
2. Canonical `fabrica-land/<repo>` syntax and exact repository allowlist are
   checked before constructing a fixed `https://api.github.com` URL.
3. The selected token source requires regular, non-symlink, runtime-owned
   `0600` credential files under a runtime-owned `0700` directory. GitHub App
   user-token refresh rotates state atomically; PAT tokens are read per request.
4. `GET /user` must resolve to `mividtim`.
5. GitHub must return the exact repository and PR, the PR must be open, and its
   head must equal `expected_head_sha`.
6. Durable SQLite idempotency (`repo + PR + head + mode`) and per-PR rate limit
   are checked.
7. A dry run returns the validated target without writing.
8. The PR and identity are re-read immediately before the fixed comment POST.
9. The created comment is read back from a broker-constructed URL. Body and
   author must exactly match, and the PR head must still be open and unchanged.
10. Request/refusal/result metadata is appended to an owner-only audit file.
    Credentials and authorization headers are never recorded.

Once a POST is attempted, any transport ambiguity, process interruption,
readback failure, or post-time head validation failure is treated as
`unsafe_posted`; automatic retry is blocked to prevent a duplicate command.
Persisted `processing` state is also fail-closed across restarts. An operator
must inspect GitHub and reconcile the state database before another attempt.

## Configuration

The broker requires:

| Variable | Purpose |
| --- | --- |
| `AGENT_ID` | Dedicated `github-review-broker@<machine>` server-plugin ID |
| `AGENT_PRIVATE_KEY` | Broker's own Wire signing key (never an agent key) |
| `WIRE_URL` | Local Wire broker URL |
| `CODERABBIT_BROKER_ALLOWED_REPOS` | Comma-separated exact repository names |
| `CODERABBIT_BROKER_ALLOWED_CALLERS_JSON` | JSON map of caller IDs to current Wire public-key arrays |
| `CODERABBIT_BROKER_TOKEN_SOURCE` | Required explicit `github_app_user` or `fine_grained_pat` selection |
| `CODERABBIT_BROKER_GITHUB_APP_CLIENT_ID` | Non-secret App client ID for the preferred source |
| `CODERABBIT_BROKER_GITHUB_APP_CLIENT_SECRET_FILE` | Owner-only App client-secret file |
| `CODERABBIT_BROKER_GITHUB_APP_USER_TOKEN_STATE_FILE` | Owner-only access/refresh token state JSON |
| `CODERABBIT_BROKER_GITHUB_APP_REFRESH_MARGIN_MS` | Optional refresh headroom; minimum/default 1/10 minutes |
| `CODERABBIT_BROKER_TOKEN_FILE` | Owner-only fine-grained PAT file; fallback source only |
| `CODERABBIT_BROKER_STATE_FILE` | Owner-only SQLite idempotency state |
| `CODERABBIT_BROKER_AUDIT_FILE` | Owner-only JSONL audit |
| `CODERABBIT_BROKER_MINIMUM_INTERVAL_MS` | Optional per-PR rate window; default 30 minutes |

The agent MCP receives only its normal Wire identity plus
`CODERABBIT_REVIEW_BROKER_AGENT_ID`. It receives no GitHub credential.

## Provisioning and release sequence

1. Complete independent security review of this branch.
2. Register or select a dedicated GitHub App for user authorization. Enable
   expiring user tokens, install it only on the allowlisted repositories, and
   grant repository metadata read plus issues/pull-request comment write—the
   minimum permissions needed for identity/PR reads and issue comments.
3. Complete the owner-operated OAuth authorization callback/bootstrap outside
   all agent runtimes. Store the client secret and initial access/refresh state
   directly in the broker's private directory. The state schema uses epoch-ms
   `expires_at` and `refresh_token_expires_at` fields and `version: 1`.
4. Create a dedicated broker runtime directory with mode `0700`.
5. Write credential/state/audit files as the broker owner with mode `0600`.
6. Enroll the dedicated broker identity and declare it as a Wire server plugin.
7. Configure exact repositories and caller ID/public-key pairs. Keep Vacherin
   absent unless explicitly approved.
8. Install the launchd unit only after review. Start with no allowed callers.
9. Run broker integration tests against a disposable private test repository,
   first dry-run and then one explicitly approved comment.
10. Obtain Tim's separate release before any Fabrica PR request.

OAuth registration still needs an operator decision: create a dedicated
GitHub App for this broker (recommended) or reuse an existing App whose callback
ownership, expiring-user-token setting, permissions, and revocation blast
radius meet this threat model.

`deploy/com.agiterra.coderabbit-review-broker.plist.example` is deliberately
non-starting (`RunAtLoad=false`, `KeepAlive=false`) and contains no credential.

## Rotation and revocation

- **Automatic App rotation:** refresh occurs inside the broker before access
  expiry; GitHub's rotated access and refresh tokens are written with fsync and
  atomic rename under the owner-only directory.
- **Reauthorize App user:** stop the broker, complete the owner OAuth flow,
  atomically replace user-token state, then restart with callers still empty.
- **Revoke App user grant:** from the broker owner identity, run
  `coderabbit-review-token-admin revoke-github-app-user --confirm-revoke-all-user-grants`.
  The command calls GitHub's fixed delete-app-authorization endpoint with
  owner-only client credentials, then removes local token state only after a
  `204` result. It is not registered as an MCP tool.
- **Rotate PAT fallback:** write a new owner-only file, `chmod 0600`, then
  atomically rename over the configured token path.
- **Revoke caller:** remove its ID/public-key entry and restart the broker.
- **Emergency stop:** unload launchd, revoke the GitHub token, and remove the
  broker from Wire's server-plugin list.
- **Rotate broker Wire key:** stop the service, rotate the enrolled permanent
  identity out of band, update the owner-only service secret, and restart.
- Preserve the audit and state database during ordinary token rotation so
  idempotency history cannot be reset accidentally.

## Rollback

1. Empty the caller map and unload the launchd unit.
2. Remove the broker identity from Wire's server-plugin list.
3. Revoke the GitHub App user authorization (or fallback PAT) and rotate the
   App client secret if exposure is suspected.
4. Preserve the owner-only audit/idempotency database for investigation; remove
   only access/refresh/client-secret material.
5. Revert the package/deployment commit. Agents retain no credential and their
   MCP client becomes a fail-closed unavailable capability.

## Validation

`bun test` covers unauthorized/unverified callers, arbitrary properties,
comment injection, SSRF and repository spoofing, closed/head-drifted PRs,
credential identity/permission/rotation, GitHub App refresh/expiry/error paths,
owner-only App-grant revocation, dry-run, duplicate requests, rate limits,
ambiguous transport, readback identity mismatch, post-time drift, and
secret-free audit.

GitHub references: [refreshing user access tokens](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/refreshing-user-access-tokens)
and [deleting an app authorization](https://docs.github.com/en/rest/apps/oauth-applications#delete-an-app-authorization).
