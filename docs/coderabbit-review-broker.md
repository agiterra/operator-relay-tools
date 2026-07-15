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
Wire message, command line, log, or audit record. The broker reads it from an
owner-only file for each request. A per-agent `github-tools` MCP extension was
rejected because that process model would delegate the credential to every
caller.

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

## Request flow

1. Strict-schema validation rejects arbitrary comment text and unknown fields.
2. Canonical `fabrica-land/<repo>` syntax and exact repository allowlist are
   checked before constructing a fixed `https://api.github.com` URL.
3. The credential file must be a regular, non-symlink, runtime-owned `0600`
   file. The token is read per request, so atomic rotation is immediate.
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
| `CODERABBIT_BROKER_TOKEN_FILE` | Owner-only GitHub user-token file |
| `CODERABBIT_BROKER_STATE_FILE` | Owner-only SQLite idempotency state |
| `CODERABBIT_BROKER_AUDIT_FILE` | Owner-only JSONL audit |
| `CODERABBIT_BROKER_MINIMUM_INTERVAL_MS` | Optional per-PR rate window; default 30 minutes |

The agent MCP receives only its normal Wire identity plus
`CODERABBIT_REVIEW_BROKER_AGENT_ID`. It receives no GitHub credential.

## Provisioning and release sequence

1. Complete independent security review of this branch.
2. Decide user-token type: GitHub App user access token or fine-grained PAT.
3. Create a dedicated broker runtime directory with mode `0700`.
4. Write credential/state/audit files as the broker owner with mode `0600`.
5. Enroll the dedicated broker identity and declare it as a Wire server plugin.
6. Configure exact repositories and caller ID/public-key pairs. Keep Vacherin
   absent unless explicitly approved.
7. Install the launchd unit only after review. Start with no allowed callers.
8. Run broker integration tests against a disposable private test repository,
   first dry-run and then one explicitly approved comment.
9. Obtain Tim's separate release before any Fabrica PR request.

`deploy/com.agiterra.coderabbit-review-broker.plist.example` is deliberately
non-starting (`RunAtLoad=false`, `KeepAlive=false`) and contains no credential.

## Rotation and revocation

- **Rotate token:** write a new owner-only file, `chmod 0600`, then atomically
  rename over the configured token path. The next request reads the new token.
- **Revoke caller:** remove its ID/public-key entry and restart the broker.
- **Emergency stop:** unload launchd, revoke the GitHub token, and remove the
  broker from Wire's server-plugin list.
- **Rotate broker Wire key:** stop the service, rotate the enrolled permanent
  identity out of band, update the owner-only service secret, and restart.
- Preserve the audit and state database during ordinary token rotation so
  idempotency history cannot be reset accidentally.

## Validation

`bun test` covers unauthorized/unverified callers, arbitrary properties,
comment injection, SSRF and repository spoofing, closed/head-drifted PRs,
credential identity/permission/rotation, dry-run, duplicate requests, rate
limits, readback identity mismatch, post-time drift, and secret-free audit.
