# V3 API security contract

## Authentication boundary

Every `/api/v1/*` operation requires the `X-API-Key` header. `/health`, `/` and
packaged assets are public but contain no operational records. OpenAPI is
disabled unless an operator starts the server with `--enable-docs`.

The API key must be at least 32 characters, is compared with
`secrets.compare_digest` and is never logged, returned or accepted in the URL.
The dashboard retains it only for the lifetime of the browser tab.

## Data minimization

API representations are constructed from explicit field allowlists. They do
not serialize database rows directly.

| Representation | Explicitly excluded |
| --- | --- |
| Run / trust report | absolute `source_uri`, internal error text |
| Lineage | `subject_token`, absolute `source_uri` |
| Sources | nested files, non-CSV files, absolute paths |
| Policy | server filesystem path |

## Write boundary

`POST /api/v1/ingestions` accepts one JSON field: `source`. The value must be a
basename ending in `.csv`, resolve beneath the configured ingestion root and
name an existing regular file. Unknown request fields, traversal, nested paths
and other extensions fail before the pipeline starts.

The configured HMAC key and trust-policy path are never caller-controlled.
Ingestion is serialized within a process. A completed run returns HTTP `201`;
its trust state may still be `breached`, because quality evidence is distinct
from HTTP transport success.

## Deployment boundary

The CLI binds to `127.0.0.1` by default. A non-loopback host requires the
operator to supply `--allow-network`. For any shared environment, place the app
behind TLS, managed authentication, rate limiting and a secrets manager.

V3 deliberately does not claim RBAC, individual actor audit, encryption at
rest or distributed locking. Those controls belong to V4.
