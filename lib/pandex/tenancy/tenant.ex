defmodule Pandex.Tenancy.Tenant do
  @moduledoc "Root isolation boundary — an organisation or workspace."
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "tenants" do
    field :name, :string
    field :slug, :string
    # JSONB column — arbitrary auth policy and UI settings
    field :settings, :map, default: %{}
    field :branding, :map, default: %{}
    field :status, :string, default: "active"

    has_many :memberships, Pandex.Tenancy.Membership
    has_many :users, through: [:memberships, :user]
    has_many :clients, Pandex.OAuth.Client

    timestamps(type: :utc_datetime)
  end

  @required [:name, :slug]
  @optional [:settings, :branding, :status]

  def changeset(tenant, attrs) do
    tenant
    |> cast(attrs, @required ++ @optional)
    |> validate_required(@required)
    |> validate_length(:name, min: 2, max: 100)
    |> validate_format(:slug, ~r/^[a-z0-9\-]+$/,
      message: "must be lowercase alphanumeric with hyphens only"
    )
    |> validate_inclusion(:status, ["active", "suspended", "deleted"])
    |> unique_constraint(:slug)
  end
end
