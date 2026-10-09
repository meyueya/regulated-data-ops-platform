# ADR 0004 — Policy-governed security boundary

- Status: accepted for V4 review
- Date: 2026-10-09

## Context

V3 authenticates requests with one shared key. That prevents anonymous access,
but cannot identify an individual, revoke one actor, segregate duties or prove
who executed a destructive operation. Operational metadata also includes host
paths and error details that should not remain as plaintext evidence.

## Decision

Replace the shared key with policy-defined principals whose API keys are stored
only as SHA-256 digests. Resolve each request to one actor and authorize it
against an explicit role-to-permission mapping. Persist authorization outcomes
and material operations in an append-only audit ledger chained by SHA-256.

Encrypt source paths, internal error messages and audit detail with AES-256-GCM.
Use a fresh 96-bit nonce for every encryption and bind each ciphertext to its
record identity through associated authenticated data. Keep the encryption key
outside policy, database and command-line arguments.

Apply retention only to accepted payment events and quarantine rows. Preserve
run summaries and the audit ledger as operational evidence. Preview is
non-destructive; execution requires the `admin` role and an exact confirmation
of the active governance-policy fingerprint. Deletion and its audit event commit
in one SQLite transaction.

## Consequences

- one leaked key no longer grants every capability;
- key revocation and role changes are policy changes with a new fingerprint;
- audit evidence identifies actor, role, decision, resource and request;
- the ledger rejects row updates/deletes and detects chain inconsistency;
- databases V1–V3 migrate additively; new V4 writes encrypt selected fields;
- SQLite pages, WAL files and non-selected columns are not fully encrypted;
- SHA-256 key digests do not compensate for weak API keys, so production keys
  must be randomly generated with high entropy;
- local RBAC demonstrates the control boundary but is not an enterprise IdP.
