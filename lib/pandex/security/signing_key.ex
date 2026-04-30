defmodule Pandex.Security.SigningKey do
  @moduledoc "RSA or EC signing key used for ID Token signatures."
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}

  schema "signing_keys" do
    field :kid, :string
    field :algorithm, :string
    # active | previous | retired
    field :status, :string, default: "active"
    # JWK public key map
    field :public_key, :map
    # Reference to KMS / secrets manager
    field :private_key_ref, :string

    timestamps(type: :utc_datetime)
  end

  def changeset(key, attrs) do
    key
    |> cast(attrs, [:kid, :algorithm, :status, :public_key, :private_key_ref])
    |> validate_required([:kid, :algorithm, :status, :public_key])
    |> validate_inclusion(:algorithm, ["RS256", "ES256"])
    |> validate_inclusion(:status, ["active", "previous", "retired"])
    |> unique_constraint(:kid)
  end
end

# ── ETS Key Cache ─────────────────────────────────────────────────────────────
