defmodule Pandex.OAuth.Client do
  @moduledoc "An OAuth 2.0 / OIDC client application registered under a tenant."
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "clients" do
    belongs_to :tenant, Pandex.Tenancy.Tenant

    field :name, :string
    # public | confidential
    field :client_type, :string, default: "public"
    # nil for public clients
    field :client_secret_hash, :string
    field :client_secret, :string, virtual: true
    field :redirect_uris, {:array, :string}, default: []
    field :allowed_scopes, {:array, :string}, default: ["openid"]
    field :allowed_grants, {:array, :string}, default: ["authorization_code"]
    field :status, :string, default: "active"
    field :settings, :map, default: %{}

    timestamps(type: :utc_datetime)
  end

  @required [:tenant_id, :name]
  @optional [:client_type, :redirect_uris, :allowed_scopes, :allowed_grants, :status, :settings]

  def changeset(client, attrs) do
    client
    |> cast(attrs, @required ++ @optional ++ [:client_secret, :client_secret_hash])
    |> validate_required(@required)
    |> validate_inclusion(:client_type, ["public", "confidential"])
    |> validate_inclusion(:status, ["active", "suspended"])
    |> validate_confidential_secret()
    |> validate_redirect_uris()
    |> hash_client_secret()
  end

  defp validate_confidential_secret(changeset) do
    client_type = get_field(changeset, :client_type)
    secret = get_change(changeset, :client_secret)
    secret_hash = get_field(changeset, :client_secret_hash)

    if client_type == "confidential" and is_nil(secret) and is_nil(secret_hash) do
      add_error(changeset, :client_secret, "is required for confidential clients")
    else
      changeset
    end
  end

  defp hash_client_secret(changeset) do
    case get_change(changeset, :client_secret) do
      nil ->
        changeset

      secret ->
        changeset
        |> validate_length(:client_secret, min: 32)
        |> put_change(:client_secret_hash, Bcrypt.hash_pwd_salt(secret))
        |> delete_change(:client_secret)
    end
  end

  defp validate_redirect_uris(changeset) do
    case get_change(changeset, :redirect_uris) do
      nil ->
        changeset

      uris ->
        if Enum.all?(uris, &valid_uri?/1),
          do: changeset,
          else: add_error(changeset, :redirect_uris, "contains an invalid URI")
    end
  end

  defp valid_uri?(uri) do
    case URI.parse(uri) do
      %URI{scheme: s, host: h} when s in ["https", "http"] and not is_nil(h) -> true
      _ -> false
    end
  end
end
