defmodule Pandex.Repo.Migrations.CreateMemberships do
  use Ecto.Migration

  def change do
    create table(:memberships, primary_key: false) do
      add :id, :binary_id, primary_key: true, null: false
      add :user_id, references(:users, type: :binary_id, on_delete: :restrict), null: false
      add :tenant_id, references(:tenants, type: :binary_id, on_delete: :restrict), null: false
      add :role, :string, null: false, default: "member"
      add :status, :string, null: false, default: "active"

      timestamps(type: :utc_datetime)
    end

    create unique_index(:memberships, [:user_id, :tenant_id])
    create index(:memberships, [:tenant_id])
    create index(:memberships, [:user_id])
  end
end
