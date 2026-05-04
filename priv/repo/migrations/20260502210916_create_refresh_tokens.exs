defmodule Pandex.Repo.Migrations.CreateRefreshTokens do
  use Ecto.Migration

  def change do
    create table(:refresh_tokens, primary_key: false) do
      add :id, :binary_id, primary_key: true, null: false
      add :user_id, references(:users, type: :binary_id, on_delete: :restrict), null: false
      add :tenant_id, references(:tenants, type: :binary_id, on_delete: :restrict), null: false
      add :client_id, references(:clients, type: :binary_id, on_delete: :restrict), null: false
      add :rotated_from_id, references(:refresh_tokens, type: :binary_id, on_delete: :nilify_all)
      add :token_hash, :string, null: false
      add :family_id, :binary_id, null: false
      add :scopes, {:array, :string}, null: false, default: []
      add :expires_at, :utc_datetime, null: false
      add :used_at, :utc_datetime
      add :revoked_at, :utc_datetime

      timestamps(type: :utc_datetime)
    end

    create unique_index(:refresh_tokens, [:token_hash])
    create index(:refresh_tokens, [:family_id])
    create index(:refresh_tokens, [:user_id, :tenant_id])
    create index(:refresh_tokens, [:expires_at])
  end
end
