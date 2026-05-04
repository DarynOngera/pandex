defmodule Pandex.Repo.Migrations.CreateLoginChallenges do
  use Ecto.Migration

  def change do
    create table(:login_challenges, primary_key: false) do
      add :id, :binary_id, primary_key: true, null: false
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false
      add :tenant_id, references(:tenants, type: :binary_id, on_delete: :restrict), null: false
      add :type, :string, null: false
      add :code_hash, :string, null: false
      add :expires_at, :utc_datetime, null: false
      add :consumed_at, :utc_datetime

      timestamps(type: :utc_datetime)
    end

    create unique_index(:login_challenges, [:code_hash])
    create index(:login_challenges, [:user_id, :tenant_id])
    create index(:login_challenges, [:expires_at])
  end
end
