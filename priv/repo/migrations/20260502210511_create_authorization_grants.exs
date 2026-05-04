defmodule Pandex.Repo.Migrations.CreateAuthorizationGrants do
  use Ecto.Migration

  def change do
    create table(:authorization_grants, primary_key: false) do
      add :id, :binary_id, primary_key: true, null: false
      add :user_id, references(:users, type: :binary_id, on_delete: :restrict), null: false
      add :client_id, references(:clients, type: :binary_id, on_delete: :restrict), null: false
      add :tenant_id, references(:tenants, type: :binary_id, on_delete: :restrict), null: false
      add :scopes, {:array, :string}, null: false, default: []
      add :consented_at, :utc_datetime

      timestamps(type: :utc_datetime)
    end

    create unique_index(:authorization_grants, [:user_id, :client_id, :tenant_id])
    create index(:authorization_grants, [:client_id])
  end
end
