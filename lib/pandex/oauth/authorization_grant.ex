defmodule Pandex.OAuth.AuthorizationGrant do
  @moduledoc "Records user consent for a client to access specific scopes."
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "authorization_grants" do
    belongs_to :user, Pandex.Accounts.User
    belongs_to :client, Pandex.OAuth.Client
    belongs_to :tenant, Pandex.Tenancy.Tenant

    field :scopes, {:array, :string}, default: []
    field :consented_at, :utc_datetime

    timestamps(type: :utc_datetime)
  end

  def changeset(grant, attrs) do
    grant
    |> cast(attrs, [:user_id, :client_id, :tenant_id, :scopes, :consented_at])
    |> validate_required([:user_id, :client_id, :tenant_id])
    |> unique_constraint([:user_id, :client_id, :tenant_id])
  end
end
