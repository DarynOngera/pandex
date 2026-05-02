# Pandex

**Multi-Tenant Identity Provider**

A conformance-first OpenID Connect provider built on **Elixir / Phoenix / PostgreSQL**.
Designed for correctness, security, and multi-tenant isolation from day one.

**Stack**

* Elixir 1.16+
* OTP 26+
* Phoenix 1.7+
* PostgreSQL 15+
* OIDC Core 1.0
* OAuth 2.0
* PKCE S256
* Multi-tenant

---

## Quick start

Pandex expects a local PostgreSQL server with these development defaults:

| Setting  | Value        |
| -------- | ------------ |
| Host     | `localhost`  |
| Port     | `5432`       |
| Username | `postgres`   |
| Password | `postgres`   |
| Database | `pandex_dev` |

To run the app locally:

```bash
# Install dependencies
mix deps.get

# Create, migrate, and seed the database
mix ecto.setup

# Start Phoenix
mix phx.server
```

Open http://localhost:4000 in your browser.

If your local Postgres user or password is different, update `config/dev.exs`
before running `mix ecto.setup`.

For endpoint flow examples and curl payloads, see [APIDOCS.md](APIDOCS.md).
For technical architecture and onboarding, see [SYSTEM_FLOW.md](SYSTEM_FLOW.md).

---

## Context architecture

### Accounts

Global user pool. Users exist once and join tenants via memberships. Email is the canonical identity.

### Tenancy

Tenant CRUD and memberships. Every DB query is scoped by `tenant_id`.

### Sessions

Browser sessions and login challenges. Magic-link codes stored as BLAKE2b hash only.

### OAuth

Clients, authorization codes, access tokens, refresh tokens. Full rotation chain with reuse detection.

### OIDC

ID Token assembly and signing via JOSE. Discovery metadata cached in ETS (5-min TTL).

### Security

Signing key lifecycle (active → previous → retired). ETS cache managed by supervised GenServer.

### Audit

Append-only event log. No `UPDATE` or `DELETE`.

### PandexWeb

Phoenix controllers + LiveView admin dashboard.

---

## Domain model

```text
Tenant ──< Membership >── User
Tenant ──< Client
User   ──< Session
User   ──< LoginChallenge
User   ──  AuthorizationGrant ──> Client
Client ──< AuthorizationCode
Client ──< AccessToken
Client ──< RefreshToken
SigningKey ── signs ──> ID Token
AuditEvent ── scoped to ──> Tenant
```

---

## Security rules

| Rule             | Description                                     |
| ---------------- | ----------------------------------------------- |
| Token storage    | BLAKE2b-256 hash only. Raw value returned once. |
| PKCE             | S256 required. `plain` rejected.                |
| Redirect URIs    | Exact match only.                               |
| Refresh rotation | Marks predecessor used + issues successor.      |
| Reuse detection  | Entire token family revoked.                    |
| Tenant boundary  | Explicit `tenant_id` required everywhere.       |
| Audit integrity  | INSERT-only table.                              |
| ETS cache        | Only keys + metadata cached.                    |

---

## OIDC endpoints

| Method | Endpoint                            | Description              |
| ------ | ----------------------------------- | ------------------------ |
| GET    | `/.well-known/openid-configuration` | Discovery metadata       |
| GET    | `/.well-known/jwks.json`            | Public signing keys      |
| GET    | `/oauth/authorize`                  | Start code flow          |
| POST   | `/oauth/token`                      | Token exchange + refresh |
| GET    | `/oauth/userinfo`                   | User claims              |
| POST   | `/oauth/revoke`                     | Token revocation         |
| POST   | `/oauth/introspect`                 | Token introspection      |

---

## Delivery phases

| Phase   | Description                             |
| ------- | --------------------------------------- |
| Phase 0 | Foundation (ADRs, schema, CI, Dialyzer) |
| Phase 1 | Tenants, users & clients                |
| Phase 2 | Passwordless auth                       |
| Phase 3 | Authorization code + PKCE               |
| Phase 4 | OIDC endpoints & ID tokens              |
| Phase 5 | Token lifecycle                         |
| Phase 6 | Admin & audit                           |
| Phase 7 | Conformance & hardening                 |

---

## Environment variables

| Variable        | Required | Description                  |
| --------------- | -------- | ---------------------------- |
| DATABASE_URL    | Yes      | PostgreSQL connection string |
| SECRET_KEY_BASE | Yes      | Phoenix secret               |
| OIDC_ISSUER     | Yes      | Public base URL              |
| POOL_SIZE       | No       | Default: 10                  |
| PORT            | No       | Default: 4000                |

---

## Static analysis

```bash
mix credo --strict   # style
mix dialyzer         # type safety
mix test             # tests
```

---

## V1 scope — not included

* Implicit & hybrid OAuth flows
* FAPI profiles
* SMS OTP
* Schema-per-tenant isolation
* External IdP federation
* JWT access tokens (opaque only)
* Normalized `scopes` table
