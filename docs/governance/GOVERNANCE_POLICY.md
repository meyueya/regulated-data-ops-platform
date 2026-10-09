# V4 governance policy

`config/governance-policy.json` is the executable source of truth for identity,
authorization and retention. Unknown keys, permissions, roles, duplicate actor
IDs and duplicate key hashes fail closed during startup.

## Principals

Each principal declares `actor_id`, display name, role, SHA-256 key digest and
enabled state. The plaintext API key is never stored. Disabling one principal
revokes only that actor after restart or policy reload.

The committed principals are synthetic demo identities. Replace every key
digest before using the application outside a local demonstration.

## Roles

Permissions are deny-by-default and exact strings. Endpoint handlers request one
permission; authentication and authorization outcomes are written to the audit
ledger with the request ID.

## Retention

The policy declares maximum age for accepted payment events and quarantine
rows. `GET /api/v1/retention-preview` returns counts and cutoffs without writing.
`POST /api/v1/retention-executions` requires:

1. an enabled `admin` principal;
2. the `retention:execute` permission;
3. the exact active governance fingerprint in the request body.

The deletions and their audit event share one transaction. Run summaries and
audit events are intentionally excluded from this retention job.

## Encryption boundary

`REGULATED_DATA_ENCRYPTION_KEY` is a URL-safe base64 encoding of exactly 32
random bytes. AES-GCM protects source URIs, internal run errors and audit detail.
Actor IDs, action names, outcomes, timestamps and event hashes remain visible so
operators can verify the chain without decrypting the evidence payload.

Key rotation requires decrypting protected fields with the old key and
re-encrypting them with a new key ID. V4 deliberately fails rather than silently
reading a ciphertext under the wrong key.
