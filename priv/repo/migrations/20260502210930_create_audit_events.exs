defmodule Pandex.Repo.Migrations.CreateAuditEvents do
  use Ecto.Migration

  def change do
    create table(:audit_events, primary_key: false) do
      add :id, :binary_id, primary_key: true, null: false
      add :tenant_id, :binary_id, null: false
      add :actor_id, :binary_id
      add :target_id, :binary_id
      add :target_type, :string
      add :event_type, :string, null: false
      add :metadata, :map, null: false, default: %{}

      timestamps(type: :utc_datetime, updated_at: false)
    end

    create index(:audit_events, [:tenant_id, :inserted_at])
    create index(:audit_events, [:tenant_id, :actor_id, :inserted_at])
    create index(:audit_events, [:tenant_id, :event_type, :inserted_at])
  end
end
