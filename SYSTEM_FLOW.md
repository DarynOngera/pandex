# Pandex System Flow and Technical Onboarding

This document explains how Pandex fits together technically, how a new engineer
should move through the codebase, and how the identity-provider flow is meant to
work end to end.

For curl payloads, see `APIDOCS.md`. This document focuses on architecture,
runtime flow, ownership boundaries, and onboarding.

## What Pandex Is

Pandex is a Phoenix and PostgreSQL application for a multi-tenant OpenID
Connect provider. Its main job is to let tenant-scoped client applications
authenticate users and receive OIDC/OAuth tokens while preserving strict tenant
boundaries.

The design center is correctness:

- Users are global.
- Tenants are the isolation boundary.
- Memberships connect users to tenants.
- OAuth clients belong to tenants.
- Authorization codes, access tokens, refresh tokens, sessions, login
  challenges, audit events, and signing keys are persisted in PostgreSQL.
- Raw secrets are returned once and never stored directly.

## Repository Map

| Path | Purpose |
| --- | --- |
| `lib/pandex` | Domain contexts and Ecto schemas. |
| `lib/pandex_web` | Phoenix router, controllers, layouts, and web boundary. |
| `priv/repo/migrations` | Timestamped database migrations. |
| `priv/repo/seeds.exs` | Local/bootstrap seed data entry point. |
| `config/*.exs` | Environment-specific application, database, endpoint, Swoosh, and Hammer configuration. |
| `test` | Phoenix controller tests and data/conn case helpers. |
| `README.md` | Project summary and quick start. |
| `APIDOCS.md` | Endpoint contract and curl examples. |

## Runtime Supervision

The application starts in `Pandex.Application`.

The supervised children are:

1. `Pandex.Repo`
   PostgreSQL access through Ecto.
2. `Pandex.Security.KeyCache`
   ETS cache for active signing keys and JWKS data.
3. `Pandex.OIDC.DiscoveryCache`
   ETS cache for OIDC discovery metadata.
4. `PandexWeb.Telemetry`
   Phoenix telemetry metrics.
5. `PandexWeb.Endpoint`
   HTTP entry point served by Bandit.

Dependency applications also start outside this tree:

- `:hammer` owns its own ETS-backed rate-limit pool from `config :hammer`.
- `:swoosh` uses `Swoosh.ApiClient.Req`.
- `:req` is the preferred HTTP client dependency.

## Database Model

The migrations create these tables:

| Table | Meaning |
| --- | --- |
| `tenants` | Tenant/workspace isolation root. |
| `users` | Global user identities. |
| `memberships` | User-to-tenant join records with role and status. |
| `clients` | OAuth/OIDC clients registered under a tenant. |
| `sessions` | Authenticated browser sessions. |
| `login_challenges` | Passwordless magic-link/OTP/passkey challenge records. |
| `authorization_codes` | Short-lived OAuth authorization codes with PKCE metadata. |
| `authorization_grants` | User consent for client scopes. |
| `access_tokens` | Opaque bearer tokens stored as hashes. |
| `refresh_tokens` | Rotating refresh tokens grouped by family. |
| `signing_keys` | OIDC signing-key metadata and public JWKs. |
| `audit_events` | Append-only audit event stream. |

Important relationship shape:

```text
Tenant -> Membership -> User
Tenant -> Client
User   -> Session
User   -> LoginChallenge
User   -> AuthorizationCode -> Client
User   -> AccessToken       -> Client
User   -> RefreshToken      -> Client
SigningKey -> signs -> ID Token
AuditEvent -> scoped to -> Tenant
```

## Context Boundaries

### Tenancy

Files:

- `lib/pandex/tenancy/tenant.ex`
- `lib/pandex/tenancy/membership.ex`
- `lib/pandex/tenancy/tenancy.ex`

Responsibilities:

- Create and update tenants.
- Add users to tenants.
- Look up memberships within a tenant boundary.

Rule of thumb: any tenant-scoped operation should receive an explicit
`tenant_id` or `%Tenant{}`.

### Accounts

Files:

- `lib/pandex/accounts/user.ex`
- `lib/pandex/accounts/accounts.ex`

Responsibilities:

- Store global users.
- Normalize email.
- Optionally hash passwords.
- Fetch a user globally or fetch a user only if they belong to a tenant.

Users are not duplicated per tenant. Memberships carry the tenant relationship.

### Sessions

Files:

- `lib/pandex/sessions/session.ex`
- `lib/pandex/sessions/login_challenge.ex`
- `lib/pandex/sessions/sessions.ex`

Responsibilities:

- Create browser sessions.
- Revoke sessions.
- Create one-time login challenges.
- Verify and consume login challenges.

Security rule: raw challenge codes are returned once. The database stores only a
BLAKE2b hash.

### OAuth

Files:

- `lib/pandex/oauth/client.ex`
- `lib/pandex/oauth/authorization_code.ex`
- `lib/pandex/oauth/authorization_grant.ex`
- `lib/pandex/oauth/access_token.ex`
- `lib/pandex/oauth/refresh_token.ex`
- `lib/pandex/oauth/oauth.ex`

Responsibilities:

- Register clients.
- Validate exact redirect URIs.
- Issue authorization codes.
- Verify PKCE.
- Issue opaque access tokens.
- Issue and rotate refresh tokens.
- Detect refresh token reuse and revoke the whole family.

Security rules:

- PKCE `S256` only.
- No wildcard redirect URI matching.
- Raw token values are returned once.
- Stored token values are BLAKE2b hashes.
- Refresh token reuse is treated as compromise.

### OIDC

Files:

- `lib/pandex/oidc/oidc.ex`
- `lib/pandex/oidc/discovery_cache.ex`

Responsibilities:

- Build discovery metadata.
- Build UserInfo claims.
- Build and verify ID tokens.
- Cache discovery metadata in ETS.

Current note: ID-token signing expects private key material from a future KMS
integration. The public JWKS route is present, but full signing needs production
key retrieval work.

### Security

Files:

- `lib/pandex/security/signing_key.ex`
- `lib/pandex/security/key_cache.ex`
- `lib/pandex/security/security.ex`

Responsibilities:

- Rotate signing keys.
- Track active, previous, and retired keys.
- Publish active and previous public keys through JWKS.
- Cache active key and JWKS in ETS.

### Audit

Files:

- `lib/pandex/audit/audit_event.ex`
- `lib/pandex/audit/audit.ex`

Responsibilities:

- Append security and admin events.
- List events by tenant, actor, or type.

Rule: audit events are insert-only. There is intentionally no update or delete
API in the context.

### Web Boundary

Files:

- `lib/pandex_web/router.ex`
- `lib/pandex_web/controllers/page_controller.ex`
- `lib/pandex_web/controllers/oidc_controller.ex`
- `lib/pandex_web/components/layouts.ex`

Currently wired routes:

| Method | Path | Controller action |
| --- | --- | --- |
| `GET` | `/` | `PandexWeb.PageController.home/2` |
| `GET` | `/.well-known/openid-configuration` | `PandexWeb.OIDCController.configuration/2` |
| `GET` | `/.well-known/jwks.json` | `PandexWeb.OIDCController.jwks/2` |
| `POST` | `/bootstrap/tenants` | `PandexWeb.BootstrapController.create_tenant/2` |
| `POST` | `/bootstrap/users` | `PandexWeb.BootstrapController.create_user/2` |
| `POST` | `/bootstrap/memberships` | `PandexWeb.BootstrapController.create_membership/2` |
| `POST` | `/bootstrap/clients` | `PandexWeb.BootstrapController.create_client/2` |
| `POST` | `/bootstrap/signing-keys` | `PandexWeb.BootstrapController.create_signing_key/2` |
| `POST` | `/login/challenges` | `PandexWeb.LoginController.create_challenge/2` |
| `POST` | `/login/challenges/consume` | `PandexWeb.LoginController.consume_challenge/2` |
| `GET` | `/oauth/authorize` | `PandexWeb.OAuthController.authorize/2` |
| `POST` | `/oauth/token` | `PandexWeb.OAuthController.token/2` |
| `GET` | `/oauth/userinfo` | `PandexWeb.OAuthController.userinfo/2` |
| `POST` | `/oauth/revoke` | `PandexWeb.OAuthController.revoke/2` |
| `POST` | `/oauth/introspect` | `PandexWeb.OAuthController.introspect/2` |

Bootstrap routes are config-gated by `:bootstrap_api_enabled`. In dev/test they
are enabled for onboarding. Keep them disabled in production unless a real admin
auth layer protects them.

## End-to-End Identity Flow

### 1. Bootstrap Tenant

A tenant is created first. It is the isolation boundary for clients, membership,
sessions, tokens, and audit events.

Context call:

```elixir
Pandex.Tenancy.create_tenant(%{
  name: "Acme",
  slug: "acme"
})
```

### 2. Create User

Users are global and email-normalized.

Context call:

```elixir
Pandex.Accounts.create_user(%{
  email: "owner@example.com",
  profile: %{
    "name" => "Owner Example"
  }
})
```

### 3. Add Membership

Membership connects the global user to the tenant.

Context call:

```elixir
Pandex.Tenancy.create_membership(%{
  tenant_id: tenant.id,
  user_id: user.id,
  role: "owner"
})
```

### 4. Register OAuth Client

The OAuth client belongs to a tenant. Redirect URIs must be exact strings.

Context call:

```elixir
Pandex.OAuth.create_client(%{
  tenant_id: tenant.id,
  name: "Demo SPA",
  client_type: "public",
  redirect_uris: ["http://localhost:5173/callback"],
  allowed_scopes: ["openid", "profile", "email"],
  allowed_grants: ["authorization_code", "refresh_token"]
})
```

### 5. Authenticate User

Passwordless login starts with a login challenge.

Context call:

```elixir
{:ok, {raw_code, challenge}} =
  Pandex.Sessions.create_login_challenge(user.id, tenant.id, :magic_link)
```

The raw code is delivered to the user and never stored directly.

Then the code is consumed:

```elixir
Pandex.Sessions.verify_and_consume_challenge(raw_code, tenant.id)
```

Once consumed, the app can create a browser session:

```elixir
Pandex.Sessions.create_session(%{
  user_id: user.id,
  tenant_id: tenant.id,
  expires_at: DateTime.add(DateTime.utc_now(), 86_400, :second)
})
```

### 6. Start Authorization Code Flow

The browser hits `/oauth/authorize` with:

- `response_type=code`
- `client_id`
- exact `redirect_uri`
- `scope`
- `state`
- `nonce`
- `code_challenge`
- `code_challenge_method=S256`

The server validates the user session, tenant membership, client, redirect URI,
scope, and PKCE metadata. It then creates an authorization code:

```elixir
Pandex.OAuth.issue_authorization_code(%{
  user_id: user.id,
  tenant_id: tenant.id,
  client_id: client.id,
  redirect_uri: "http://localhost:5173/callback",
  scopes: ["openid", "profile", "email"],
  code_challenge: code_challenge,
  code_challenge_method: "S256",
  nonce: nonce
})
```

The raw authorization code is sent to the client through a redirect. Only the
hash is stored.

### 7. Exchange Code For Tokens

The client posts the raw code and `code_verifier` to `/oauth/token`.

The server hashes the code, fetches the stored code, verifies it is unused and
unexpired, then verifies PKCE:

```elixir
Pandex.OAuth.exchange_authorization_code(raw_code, code_verifier, client.id)
```

After the code is consumed, the server issues:

- opaque access token
- refresh token
- ID token

Access token:

```elixir
Pandex.OAuth.issue_access_token(%{
  user_id: user.id,
  tenant_id: tenant.id,
  client_id: client.id,
  scopes: ["openid", "profile", "email"]
})
```

Refresh token:

```elixir
Pandex.OAuth.issue_refresh_token(%{
  user_id: user.id,
  tenant_id: tenant.id,
  client_id: client.id,
  scopes: ["openid", "profile", "email"],
  expires_at: DateTime.add(DateTime.utc_now(), 30 * 86_400, :second)
})
```

ID token:

```elixir
Pandex.OIDC.build_id_token(user, client.id,
  nonce: nonce,
  scopes: ["openid", "profile", "email"]
)
```

### 8. Call UserInfo

The resource server or client presents a bearer access token.

The server introspects the raw token:

```elixir
Pandex.OAuth.introspect_access_token(raw_access_token)
```

Then it builds claims from the user and granted scopes:

```elixir
Pandex.OIDC.build_userinfo(user, ["openid", "profile", "email"])
```

### 9. Refresh Token Rotation

When a refresh token is used, the server:

1. Hashes the inbound raw token.
2. Finds the token record.
3. Rejects missing, revoked, expired, or already-used tokens.
4. Marks the current token as used.
5. Issues a successor token in the same family.

Context call:

```elixir
Pandex.OAuth.rotate_refresh_token(raw_refresh_token)
```

If a used refresh token appears again, Pandex revokes the entire family.

### 10. Audit Sensitive Events

Security-sensitive actions should emit audit events:

- login success
- login failure
- token issued
- token revoked
- token rotated
- refresh token reuse detected
- client created
- client updated
- user suspended
- signing key rotated
- admin action

Context call:

```elixir
Pandex.Audit.log(tenant.id, "token_issued", %{
  actor_id: user.id,
  target_id: client.id,
  target_type: "client",
  metadata: %{"grant_type" => "authorization_code"}
})
```

When possible, call audit logging inside the same `Ecto.Multi` or transaction as
the mutation being audited.

## Request Lifecycle

For an HTTP request:

1. `PandexWeb.Endpoint` receives the request.
2. `PandexWeb.Router` matches the route.
3. The route pipeline runs:
   - browser pipeline for HTML
   - API pipeline for JSON
4. A controller calls a domain context.
5. The context validates data through schema changesets.
6. The context reads or writes through `Pandex.Repo`.
7. The controller renders HTML or JSON.

Keep controllers thin. Most business rules belong in contexts.

## Caches

### Discovery Cache

`Pandex.OIDC.DiscoveryCache` stores OIDC metadata in ETS for five minutes.

The discovery document is deterministic for a given issuer, so caching avoids
rebuilding it on every request.

### Key Cache

`Pandex.Security.KeyCache` stores:

- the active signing key
- the JWKS key list

Key rotation invalidates the cache. If a cache miss occurs, the security context
loads from PostgreSQL.

## Configuration

Important config values:

| Config | Purpose |
| --- | --- |
| `config :pandex, :oidc_issuer` | Issuer used in discovery metadata and ID tokens. |
| `config :pandex, Pandex.Repo` | Database connection settings. |
| `config :hammer` | Hammer ETS backend config for rate limiting. |
| `config :swoosh, :api_client` | Email API client; this project uses `Swoosh.ApiClient.Req`. |
| `config :pandex, PandexWeb.Endpoint` | Phoenix endpoint and LiveView settings. |

Development and test database credentials are environment-specific. If `mix
test` or `mix precommit` fails at database creation, check `config/test.exs`.

## Local Onboarding Checklist

1. Install Elixir, Erlang/OTP, PostgreSQL, and project dependencies.
2. Confirm PostgreSQL is running.
3. Confirm `config/dev.exs` matches your local database user and password.
4. Run `mix deps.get`.
5. Run `mix ecto.setup`.
6. Run `mix phx.server`.
7. Check:

```bash
curl -i http://localhost:4000/
curl -i http://localhost:4000/.well-known/openid-configuration
curl -i http://localhost:4000/.well-known/jwks.json
```

8. Run focused tests while developing:

```bash
mix test test/pandex_web/controllers/oidc_controller_test.exs
```

9. Run the full precommit before handing off work:

```bash
mix precommit
```

## Adding A New Endpoint

1. Add or extend the domain context first.
2. Add a controller under `lib/pandex_web/controllers`.
3. Add a route in `PandexWeb.Router`.
4. Keep request parsing, response status, and rendering in the controller.
5. Keep validation and business behavior in the context/schema.
6. Add tests under `test/pandex_web/controllers`.
7. Update `APIDOCS.md` with curl examples.
8. Update this document if the system flow changes.

## Adding A New Table

1. Generate the migration:

```bash
mix ecto.gen.migration create_example_records
```

2. Edit the generated timestamped migration.
3. Add the schema under the appropriate context directory.
4. Add changesets with required fields and database constraints.
5. Add context functions.
6. Add tests.
7. Run `mix precommit`.

Do not create aggregate migration files. Each migration belongs in its own
timestamped file.

## Current Implementation Gaps

These parts are represented in the domain model or docs but still need full HTTP
implementation:

- Browser session/cookie-backed authorization. The current authorization
  endpoint accepts a temporary `session_id` parameter.
- Production KMS/private-key retrieval for ID-token signing. Dev/test signing
  stores a local private JWK reference in the database for onboarding.
- Audit integration around every security-sensitive mutation.
- Rate-limit plugs around login, token, and introspection endpoints.

## Mental Model For New Contributors

When you are unsure where code belongs, use this rule:

- Database shape lives in migrations and schemas.
- Validation lives in changesets.
- Business rules live in contexts.
- HTTP shape lives in controllers.
- Route ownership lives in the router.
- Shared HTML layout lives in `PandexWeb.Layouts`.
- Operational setup lives in config and seeds.
- End-user HTTP examples live in `APIDOCS.md`.

That separation keeps the identity-provider logic testable without needing every
test to go through HTTP.
