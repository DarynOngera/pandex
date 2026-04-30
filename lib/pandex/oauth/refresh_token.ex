defmodule Pandex.OAuth.RefreshToken do
  @moduledoc """
  Refresh token with rotation chain.

  - `family_id`     groups tokens issued for the same original grant.
  - `rotated_from`  points to the predecessor token.
  - `used_at`       marks a token as consumed — reuse signals compromise.
  - `revoked_at`    set on all family members during family revocation.
  """
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "refresh_tokens" do
    belongs_to :user, Pandex.Accounts.User
    belongs_to :tenant, Pandex.Tenancy.Tenant
    belongs_to :client, Pandex.OAuth.Client
    belongs_to :rotated_from, Pandex.OAuth.RefreshToken, foreign_key: :rotated_from_id

    field :token_hash, :string
    field :family_id, :binary_id
    field :scopes, {:array, :string}, default: []
    field :used_at, :utc_datetime
    field :revoked_at, :utc_datetime
    field :expires_at, :utc_datetime

    timestamps(type: :utc_datetime)
  end

  def changeset(token, attrs) do
    token
    |> cast(attrs, [
      :user_id,
      :tenant_id,
      :client_id,
      :token_hash,
      :family_id,
      :rotated_from_id,
      :scopes,
      :expires_at
    ])
    |> validate_required([:user_id, :tenant_id, :client_id, :token_hash, :family_id])
    |> unique_constraint(:token_hash)
  end
end
