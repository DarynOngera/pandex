defmodule Pandex.Tenancy.Membership do
  @moduledoc "Junction table connecting users to tenants with a role."
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "memberships" do
    belongs_to :user, Pandex.Accounts.User
    belongs_to :tenant, Pandex.Tenancy.Tenant

    field :role, :string, default: "member"
    field :status, :string, default: "active"

    timestamps(type: :utc_datetime)
  end

  @roles ~w(owner admin member read_only)
  @statuses ~w(active suspended)

  def changeset(membership, attrs) do
    membership
    |> cast(attrs, [:user_id, :tenant_id, :role, :status])
    |> validate_required([:user_id, :tenant_id])
    |> validate_inclusion(:role, @roles)
    |> validate_inclusion(:status, @statuses)
    |> unique_constraint([:user_id, :tenant_id])
  end
end
