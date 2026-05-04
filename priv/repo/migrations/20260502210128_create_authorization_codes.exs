defmodule Pandex.Repo.Migrations.CreateAuthorizationCodes do
  use Ecto.Migration

  def change do
    create table(:authorization_codes, primary_key: false) do
      add :id, :binary_id, primary_key: true, null: false
      add :user_id, references(:users, type: :binary_id, on_delete: :restrict), null: false
      add :tenant_id, references(:tenants, type: :binary_id, on_delete: :restrict), null: false
      add :client_id, references(:clients, type: :binary_id, on_delete: :restrict), null: false
      add :code_hash, :string, null: false
      add :redirect_uri, :string, null: false
      add :scopes, {:array, :string}, null: false, default: []
      add :code_challenge, :string, null: false
      add :code_challenge_method, :string, null: false, default: "S256"
      add :nonce, :string
      add :expires_at, :utc_datetime, null: false
      add :used_at, :utc_datetime

      timestamps(type: :utc_datetime)
    end

    create unique_index(:authorization_codes, [:code_hash])
    create index(:authorization_codes, [:client_id])
    create index(:authorization_codes, [:expires_at])
  end
end
