# ADR 0003 — Authenticated operations plane

- Status: accepted for V3 review
- Date: 2026-07-31

## Context

V2 exposes trustworthy evidence through a local CLI, but operators cannot see
or invoke it from a cohesive application. Adding HTTP creates new risks:
unauthorized reads, arbitrary file selection, leaking internal paths or tokens,
and accidental network exposure.

## Decision

Build a same-origin FastAPI application with a packaged, dependency-free
dashboard. Protect every data route with one environment-supplied API key.
Keep `/health` and static UI public. Select ingestion inputs only from flat CSV
files beneath a server-configured root. Return DTOs composed from explicit
field allowlists and bind the development server to loopback by default.

The dashboard stores the key in `sessionStorage`, renders API values with DOM
text nodes and loads no CDN resources. API responses receive `no-store` and
all responses receive CSP, anti-frame, no-sniff, no-referrer and request-ID
headers.

## Consequences

- V3 is runnable with one Python install and no Node toolchain.
- Existing V1/V2 CLI and data-plane semantics remain unchanged.
- The web surface can demonstrate full-stack operations without disclosing
  pseudonymous identity or host paths.
- One shared key is authentication, not authorization. It does not establish
  roles or individual accountability; that remains an explicit V4 concern.
- The in-process ingestion lock is appropriate for the local demonstration,
  not a substitute for distributed orchestration.
