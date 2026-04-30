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
    |> cast(attrs, @required ++ @optional ++ [:client_secret_hash])
    |> validate_required(@required)
    |> validate_inclusion(:client_type, ["public", "confidential"])
    |> validate_inclusion(:status, ["active", "suspended"])
    |> validate_redirect_uris()
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
