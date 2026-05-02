defmodule PandexWeb.Router do
  use PandexWeb, :router

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

  scope "/", PandexWeb do
    pipe_through :browser

    get "/", PageController, :home
  end

  scope "/", PandexWeb do
    pipe_through :api

    get "/.well-known/openid-configuration", OIDCController, :configuration
    get "/.well-known/jwks.json", OIDCController, :jwks

    post "/bootstrap/tenants", BootstrapController, :create_tenant
    post "/bootstrap/users", BootstrapController, :create_user
    post "/bootstrap/memberships", BootstrapController, :create_membership
    post "/bootstrap/clients", BootstrapController, :create_client
    post "/bootstrap/signing-keys", BootstrapController, :create_signing_key

    post "/login/challenges", LoginController, :create_challenge
    post "/login/challenges/consume", LoginController, :consume_challenge

    get "/oauth/authorize", OAuthController, :authorize
    post "/oauth/token", OAuthController, :token
    get "/oauth/userinfo", OAuthController, :userinfo
    post "/oauth/introspect", OAuthController, :introspect
    post "/oauth/revoke", OAuthController, :revoke
  end
end
