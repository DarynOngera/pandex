defmodule Pandex.Repo.Migrations.CreateSessions do
  use Ecto.Migration

  def change do
    create table(:sessions, primary_key: false) do
      add :id, :binary_id, primary_key: true, null: false
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false
      add :tenant_id, references(:tenants, type: :binary_id, on_delete: :restrict), null: false
      add :device_metadata, :map, null: false, default: %{}
      add :ip_address, :string
      add :expires_at, :utc_datetime, null: false
      add :revoked_at, :utc_datetime

      timestamps(type: :utc_datetime)
    end

    create index(:sessions, [:user_id])
    create index(:sessions, [:tenant_id])
    create index(:sessions, [:expires_at])
  end
end
