defmodule Pandex.Repo.Migrations.CreateClients do
  use Ecto.Migration

  def change do
    create table(:clients, primary_key: false) do
      add :id, :binary_id, primary_key: true, null: false
      add :tenant_id, references(:tenants, type: :binary_id, on_delete: :restrict), null: false
      add :name, :string, null: false
      add :client_type, :string, null: false, default: "public"
      add :client_secret_hash, :string
      add :redirect_uris, {:array, :string}, null: false, default: []
      add :allowed_scopes, {:array, :string}, null: false, default: ["openid"]
      add :allowed_grants, {:array, :string}, null: false, default: ["authorization_code"]
      add :status, :string, null: false, default: "active"
      add :settings, :map, null: false, default: %{}

      timestamps(type: :utc_datetime)
    end

    create index(:clients, [:tenant_id])
    create index(:clients, [:status])
  end
end
