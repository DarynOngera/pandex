defmodule PandexWeb.Router do
  use PandexWeb, :router

  # ── Pipelines ──────────────────────────────────────────────────────────────

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {PandexWeb.Layouts, :root}
    plug :put_layout, false
    plug :protect_from_forgery
    plug :put_secure_browser_headers
  end

  pipeline :api do
    plug :accepts, ["json"]
  end

  # Used by the /oauth/authorize endpoint. Accepts JSON or HTML (the authorize
  # endpoint may redirect or render an error page in future). Fetches cookies
  # so SessionAuth can read the pandex_session_id cookie, but skips CSRF
  # protection because this route is accessed via cross-origin redirect from
  # the client application (no form submission, GET only).
  pipeline :oauth_browser do
    plug :accepts, ["html", "json"]
    plug :fetch_session
    plug :fetch_cookies
    plug PandexWeb.Plugs.SessionAuth, required: false
  end

  # ── Routes ─────────────────────────────────────────────────────────────────

  scope "/", PandexWeb do
    pipe_through :browser

    get "/", PageController, :home
  end

  scope "/", PandexWeb do
    pipe_through :api

    # ── OIDC discovery ───────────────────────────────────────────────────────
    get "/.well-known/openid-configuration", OIDCController, :configuration
    get "/.well-known/jwks.json", OIDCController, :jwks

    # ── Bootstrap (dev/test only — gated by ensure_bootstrap_enabled plug) ──
    post "/bootstrap/tenants", BootstrapController, :create_tenant
    post "/bootstrap/users", BootstrapController, :create_user
    post "/bootstrap/memberships", BootstrapController, :create_membership
    post "/bootstrap/clients", BootstrapController, :create_client
    post "/bootstrap/signing-keys", BootstrapController, :create_signing_key

    # ── Passwordless login (API flow) ────────────────────────────────────────
    post "/login/challenges", LoginController, :create_challenge
    post "/login/challenges/consume", LoginController, :consume_challenge

    # ── Browser session management ───────────────────────────────────────────
    # POST /session    — consume a challenge code, set session cookie
    # DELETE /session  — revoke session, clear cookie
    post "/session", SessionController, :create
    delete "/session", SessionController, :delete

    # ── OAuth / OIDC token endpoints ─────────────────────────────────────────
    post "/oauth/token", OAuthController, :token
    get "/oauth/userinfo", OAuthController, :userinfo
    post "/oauth/introspect", OAuthController, :introspect
    post "/oauth/revoke", OAuthController, :revoke
  end

  # /oauth/authorize uses the oauth_browser pipeline so it can read cookies
  # and redirect back to the client application.
  scope "/", PandexWeb do
    pipe_through :oauth_browser

    get "/oauth/authorize", OAuthController, :authorize
  end

  # ── Dev-only routes ─────────────────────────────────────────────────────────
  if Mix.env() == :dev do
    # Browse sent emails at http://localhost:4000/dev/mailbox
    # Requires: {:plug_swoosh, "~> 0.3", only: :dev} in mix.exs
    forward "/dev/mailbox", Plug.Swoosh.MailboxPreview
  end
end
