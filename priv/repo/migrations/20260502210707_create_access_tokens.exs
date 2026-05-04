defmodule Pandex.Repo.Migrations.CreateAccessTokens do
  use Ecto.Migration

  def change do
    create table(:access_tokens, primary_key: false) do
      add :id, :binary_id, primary_key: true, null: false
      add :user_id, references(:users, type: :binary_id, on_delete: :restrict), null: false
      add :tenant_id, references(:tenants, type: :binary_id, on_delete: :restrict), null: false
      add :client_id, references(:clients, type: :binary_id, on_delete: :restrict), null: false
      add :token_hash, :string, null: false
      add :scopes, {:array, :string}, null: false, default: []
      add :expires_at, :utc_datetime, null: false
      add :revoked_at, :utc_datetime

      timestamps(type: :utc_datetime)
    end

    create unique_index(:access_tokens, [:token_hash])
    create index(:access_tokens, [:user_id, :tenant_id])
    create index(:access_tokens, [:expires_at])
  end
end
