# Pandex

Multi-tenant OpenID Connect provider built on Elixir / Phoenix / PostgreSQL.
Designed for protocol correctness and strict tenant isolation from the start.

**Stack:** Elixir 1.16+ · OTP 26+ · Phoenix 1.7+ · PostgreSQL 15+  
**Protocols:** OIDC Core 1.0 · OAuth 2.0 · PKCE S256

---

## Quick start

Pandex expects a local PostgreSQL instance with these defaults:

| Setting  | Value        |
| -------- | ------------ |
| Host     | `localhost`  |
| Port     | `5432`       |
| Username | `postgres`   |
| Password | `postgres`   |
| Database | `pandex_dev` |

Override these in `config/dev.exs` before running setup.

```bash
mix deps.get
mix ecto.setup   # create, migrate, seed
mix phx.server   # → http://localhost:4000
```

Verify the server is up:

```bash
curl http://localhost:4000/.well-known/openid-configuration
curl http://localhost:4000/.well-known/jwks.json
```

For full endpoint contracts and curl examples, see [APIDOCS.md](APIDOCS.md).  
For architecture, flow diagrams, and onboarding guidance, see [SYSTEM_FLOW.md](SYSTEM_FLOW.md).

---

## Development workflow

```bash
mix precommit        # format + compile (warnings-as-errors) + test — run before every push
mix test             # tests only
mix credo --strict   # style and readability
mix dialyzer         # type correctness
```

Run a single test file while developing:

```bash
mix test test/pandex_web/controllers/oidc_controller_test.exs
```

---

## Bootstrap API

The bootstrap API creates tenants, users, memberships, clients, and signing keys
over HTTP. It is enabled in dev and test via config:

```elixir
# config/dev.exs
config :pandex, :bootstrap_api_enabled, true
```

Keep this disabled in production unless the routes are protected by an auth layer.

```bash
# Create a tenant
curl -X POST http://localhost:4000/bootstrap/tenants \
  -H "Content-Type: application/json" \
  -d '{"name": "Acme", "slug": "acme"}'

# Generate a signing key (required before any token can be issued)
curl -X POST http://localhost:4000/bootstrap/signing-keys \
  -H "Content-Type: application/json" \
  -d '{"algorithm": "RS256"}'
```

`Security.ensure_active_signing_key/1` is called during the token endpoint flow
and will auto-generate a key if none exists — useful in dev, but do not rely on
this in production.

---

## Identity flow summary

```
Bootstrap tenant → create user → add membership → register client
    → create login challenge → consume challenge → create session
        → /oauth/authorize → /oauth/token → access token + refresh token + ID token
```

### Passwordless login

```bash
# 1. Request a challenge (magic link / OTP)
POST /login/challenges
{ "tenant_id": "<id>", "email": "user@example.com", "type": "magic_link" }

# 2. Consume it (exchange for a session)
POST /login/challenges/consume
{ "tenant_id": "<id>", "code": "<raw_code>" }
# → returns session_id
```

In dev, set `config :pandex, :expose_login_challenge_codes, true` to receive the
raw code directly in the response instead of delivering it by email.

### Authorization code + PKCE

```bash
GET /oauth/authorize
  ?client_id=<id>
  &redirect_uri=<exact_uri>
  &response_type=code
  &scope=openid+profile+email
  &code_challenge=<s256_challenge>
  &code_challenge_method=S256
  &state=<state>
  &nonce=<nonce>
  &session_id=<session_id>          # current auth mechanism; cookie-backed flow is pending
```

The server validates the session, tenant membership, client, redirect URI, scope,
and PKCE metadata before issuing a code.

### Token exchange

```bash
POST /oauth/token
  grant_type=authorization_code
  &client_id=<id>
  &code=<raw_code>
  &code_verifier=<verifier>
  &redirect_uri=<exact_uri>
```

Returns `access_token`, `refresh_token`, `id_token`, `expires_in`, and `scope`.

---

## Context map

| Context | Owns |
| ------- | ---- |
| `Pandex.Accounts` | Users (global pool, email-normalized) |
| `Pandex.Tenancy` | Tenants, Memberships |
| `Pandex.Sessions` | Browser sessions, Login challenges |
| `Pandex.OAuth` | Clients, Authorization codes, Access tokens, Refresh tokens |
| `Pandex.OIDC` | ID Token assembly, UserInfo claims, Discovery metadata |
| `Pandex.Security` | Signing keys, ETS key cache |
| `Pandex.Audit` | Append-only event log |
| `PandexWeb` | Phoenix controllers, Router |

Domain rule: every context function that touches tenant-scoped data requires an
explicit `tenant_id`. There are no implicit cross-tenant queries.

---

## Domain model

```
Tenant ──< Membership >── User
Tenant ──< Client
User   ──< Session
User   ──< LoginChallenge
User   ──  AuthorizationGrant ──> Client
Client ──< AuthorizationCode
Client ──< AccessToken
Client ──< RefreshToken
SigningKey ── signs ──> ID Token   (not stored — assembled and signed on demand)
AuditEvent ── scoped to ──> Tenant
```

---

## Security rules

| Rule | Detail |
| ---- | ------ |
| Token storage | BLAKE2b-256 hash only. Raw value returned once, never written to DB or logs. |
| PKCE | S256 required. `plain` is rejected unconditionally. |
| Redirect URIs | Byte-for-byte exact match. No wildcards, no prefix matching. |
| Refresh rotation | Each exchange marks the predecessor `used_at` and issues a successor. |
| Reuse detection | Presenting a used refresh token revokes the entire token family atomically. |
| Tenant boundary | Explicit `tenant_id` required in every context query. |
| Audit integrity | `audit_events` is INSERT-only. No UPDATE or DELETE in application code. |
| ETS cache | Read-acceleration only for signing keys and discovery metadata. Tokens and sessions are never cached. |
| Client secrets | Stored as Bcrypt hash. Confidential clients require a secret of 32+ chars. |

---

## OIDC endpoints

| Method | Path | Description |
| ------ | ---- | ----------- |
| GET | `/.well-known/openid-configuration` | Discovery metadata |
| GET | `/.well-known/jwks.json` | Public signing keys (JWKS) |
| GET | `/oauth/authorize` | Start authorization code flow |
| POST | `/oauth/token` | Code exchange and refresh token rotation |
| GET | `/oauth/userinfo` | User claims for bearer token subject |
| POST | `/oauth/revoke` | Token revocation (RFC 7009) |
| POST | `/oauth/introspect` | Token introspection (RFC 7662) |

---

## Environment variables

| Variable | Required | Description |
| -------- | -------- | ----------- |
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `SECRET_KEY_BASE` | Yes | Phoenix session secret — 64+ characters |
| `OIDC_ISSUER` | Yes | Public HTTPS base URL, e.g. `https://id.example.com` |
| `POOL_SIZE` | No | DB connection pool size (default: 10) |
| `PORT` | No | HTTP listen port (default: 4000) |

---

## Adding a table

```bash
mix ecto.gen.migration create_<name>
# edit the generated migration file
# add schema + changeset in the relevant context directory
# add context functions + tests
mix precommit
```

Do not aggregate migrations into a single file. Each migration belongs in its
own timestamped file under `priv/repo/migrations/`.

---

## Current gaps

These are tracked and not yet implemented:

- Cookie-backed browser session authentication. The authorize endpoint currently
  accepts a `session_id` query parameter as a temporary mechanism.
- Production KMS integration for ID token private key retrieval. Dev uses a
  local JWK reference encoded in `private_key_ref`.
- Rate-limit plugs around the login, token, and introspection endpoints.
- Audit event emission around every security-sensitive mutation.

---

## V1 scope — not included

- Implicit and hybrid OAuth flows
- FAPI 1.0 / 2.0 profiles
- SMS OTP (magic-link email only in V1)
- Schema-per-tenant database isolation
- External IdP federation (SAML, social login)
- JWT-format access tokens (opaque only)
- Normalised `scopes` table (stored as arrays on tokens and clients)
