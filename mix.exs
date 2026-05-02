defmodule Pandex.MixProject do
  use Mix.Project

  def project do
    [
      app: :pandex,
      version: "0.1.0",
      elixir: "~> 1.16",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      aliases: aliases(),
      deps: deps(),
      # Dialyzer
      dialyzer: [
        plt_add_apps: [:mix],
        flags: [:error_handling, :underspecs]
      ]
    ]
  end

  def cli do
    [
      preferred_envs: [precommit: :test]
    ]
  end

  def application do
    [
      mod: {Pandex.Application, []},
      extra_applications: [:logger, :runtime_tools, :crypto]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      # Phoenix
      {:phoenix, "~> 1.7"},
      {:phoenix_live_view, "~> 0.20"},
      {:phoenix_ecto, "~> 4.4"},
      {:phoenix_html, "~> 4.0"},
      {:gettext, "~> 1.0"},

      # Database
      {:ecto_sql, "~> 3.11"},
      {:postgrex, ">= 0.0.0"},

      # Cryptography & JWT
      {:jose, "~> 1.11"},
      {:bcrypt_elixir, "~> 3.0"},
      {:comeonin, "~> 5.3"},

      # HTTP server
      {:bandit, "~> 1.2"},
      {:plug_cowboy, "~> 2.6"},

      # Rate limiting
      {:hammer, "~> 6.1"},

      # Observability
      {:telemetry_metrics, "~> 0.6"},
      {:telemetry_poller, "~> 1.0"},

      # Email (passwordless)
      {:swoosh, "~> 1.14"},
      {:req, "~> 0.5.10"},

      # Dev / test
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:stream_data, "~> 0.6", only: [:dev, :test]},
      {:phoenix_live_reload, "~> 1.2", only: :dev},
      {:floki, ">= 0.30.0", only: :test}
    ]
  end

  defp aliases do
    [
      setup: ["deps.get", "ecto.setup"],
      "ecto.setup": ["ecto.create", "ecto.migrate", "run priv/repo/seeds.exs"],
      "ecto.reset": ["ecto.drop", "ecto.setup"],
      precommit: ["format", "compile --warnings-as-errors", "test"],
      test: ["ecto.create --quiet", "ecto.migrate --quiet", "test"]
    ]
  end
end
