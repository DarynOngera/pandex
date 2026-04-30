# This file is responsible for configuring your application
# and its dependencies with the aid of the Config module.
#
# This configuration file is loaded before any dependency and
# is restricted to this project.

# General application configuration
import Config

config :pandex,
  ecto_repos: [Pandex.Repo],
  generators: [timestamp_type: :utc_datetime, binary_id: true],
  oidc_issuer: "http://localhost:4000"

config :pandex, Pandex.Repo,
  database: "pandex_dev",
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  port: 5432

config :hammer,
  backend:
    {Hammer.Backend.ETS, [expiry_ms: :timer.minutes(60), cleanup_interval_ms: :timer.minutes(10)]}

# Configure the endpoint
config :pandex, PandexWeb.Endpoint,
  url: [host: "localhost"],
  adapter: Bandit.PhoenixAdapter,
  render_errors: [
    formats: [html: PandexWeb.ErrorHTML, json: PandexWeb.ErrorJSON],
    layout: false
  ],
  pubsub_server: Pandex.PubSub,
  live_view: [signing_salt: "+5EuLXpx"]

# Configure Elixir's Logger
config :logger, :default_formatter,
  format: "$time $metadata[$level] $message\n",
  metadata: [:request_id]

# Use Jason for JSON parsing in Phoenix
config :phoenix, :json_library, Jason

# Import environment specific config. This must remain at the bottom
# of this file so it overrides the configuration defined above.
import_config "#{config_env()}.exs"
