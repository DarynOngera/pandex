defmodule Pandex.OAuth.AuthorizationCode do
  @moduledoc "Short-lived authorization code (TTL: 60 s). Stores PKCE challenge."
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "authorization_codes" do
    belongs_to :user, Pandex.Accounts.User
    belongs_to :tenant, Pandex.Tenancy.Tenant
    belongs_to :client, Pandex.OAuth.Client

    field :code_hash, :string
    field :redirect_uri, :string
    field :scopes, {:array, :string}, default: []
    field :code_challenge, :string
    field :code_challenge_method, :string, default: "S256"
    # forwarded into ID Token
    field :nonce, :string
    field :expires_at, :utc_datetime
    field :used_at, :utc_datetime

    timestamps(type: :utc_datetime)
  end

  def changeset(code, attrs) do
    code
    |> cast(attrs, [
      :user_id,
      :tenant_id,
      :client_id,
      :code_hash,
      :redirect_uri,
      :scopes,
      :code_challenge,
      :code_challenge_method,
      :nonce,
      :expires_at
    ])
    |> validate_required([
      :user_id,
      :tenant_id,
      :client_id,
      :code_hash,
      :code_challenge,
      :expires_at
    ])
    |> validate_inclusion(:code_challenge_method, ["S256"])
  end
end
