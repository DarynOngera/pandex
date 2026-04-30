defmodule Pandex.Sessions.Session do
  @moduledoc "Tracks an authenticated browser session."
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "sessions" do
    belongs_to :user, Pandex.Accounts.User
    belongs_to :tenant, Pandex.Tenancy.Tenant

    field :device_metadata, :map, default: %{}
    field :ip_address, :string
    field :expires_at, :utc_datetime
    field :revoked_at, :utc_datetime

    timestamps(type: :utc_datetime)
  end

  def changeset(session, attrs) do
    session
    |> cast(attrs, [:user_id, :tenant_id, :device_metadata, :ip_address, :expires_at])
    |> validate_required([:user_id, :tenant_id, :expires_at])
  end
end
