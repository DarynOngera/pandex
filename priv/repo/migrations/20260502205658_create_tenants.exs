defmodule Pandex.Repo.Migrations.CreateTenants do
  use Ecto.Migration

  def change do
    create table(:tenants, primary_key: false) do
      add :id, :binary_id, primary_key: true, null: false
      add :name, :string, null: false
      add :slug, :string, null: false
      add :status, :string, null: false, default: "active"
      add :settings, :map, null: false, default: %{}
      add :branding, :map, null: false, default: %{}

      timestamps(type: :utc_datetime)
    end

    create unique_index(:tenants, [:slug])
    create index(:tenants, [:status])
  end
end
