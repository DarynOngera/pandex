defmodule Pandex.Application do
  @moduledoc """
  OTP Application entry-point.

  Supervision tree layout:
    Pandex.Application
    ├── Pandex.Repo                         (Ecto / PostgreSQL)
    ├── Pandex.Security.KeyCache            (ETS – signing key read cache)
    ├── Pandex.OIDC.DiscoveryCache          (ETS – .well-known metadata cache)
    ├── PandexWeb.Telemetry                 (Telemetry supervisor)
    └── PandexWeb.Endpoint                  (Phoenix HTTP endpoint)
  """
  use Application

  @impl true
  def start(_type, _args) do
    children = [
      # ── Persistence ───────────────────────────────────────────────────────
      Pandex.Repo,

      # ── Read caches (ETS-backed GenServers) ───────────────────────────────
      Pandex.Security.KeyCache,
      Pandex.OIDC.DiscoveryCache,

      # ── Observability ─────────────────────────────────────────────────────
      PandexWeb.Telemetry,

      # ── Phoenix HTTP endpoint ─────────────────────────────────────────────
      PandexWeb.Endpoint
    ]

    opts = [strategy: :one_for_one, name: Pandex.Supervisor]
    Supervisor.start_link(children, opts)
  end

  @impl true
  def config_change(changed, _new, removed) do
    PandexWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end
