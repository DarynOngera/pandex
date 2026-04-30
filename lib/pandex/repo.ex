defmodule Pandex.Repo do
  use Ecto.Repo,
    otp_app: :pandex,
    adapter: Ecto.Adapters.Postgres
end
