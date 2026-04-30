defmodule Pandex.OAuth.AccessToken do
  @moduledoc "Opaque bearer token. Only its BLAKE2b hash is persisted."
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "access_tokens" do
    belongs_to :user, Pandex.Accounts.User
    belongs_to :tenant, Pandex.Tenancy.Tenant
    belongs_to :client, Pandex.OAuth.Client

    field :token_hash, :string
    field :scopes, {:array, :string}, default: []
    field :expires_at, :utc_datetime
    field :revoked_at, :utc_datetime

    timestamps(type: :utc_datetime)
  end

  def changeset(token, attrs) do
    token
    |> cast(attrs, [:user_id, :tenant_id, :client_id, :token_hash, :scopes, :expires_at])
    |> validate_required([:user_id, :tenant_id, :client_id, :token_hash, :expires_at])
    |> unique_constraint(:token_hash)
  end
end
