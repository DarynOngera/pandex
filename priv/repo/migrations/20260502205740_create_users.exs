defmodule Pandex.Repo.Migrations.CreateUsers do
  use Ecto.Migration

  def change do
    create table(:users, primary_key: false) do
      add :id, :binary_id, primary_key: true, null: false
      add :email, :string, null: false
      add :status, :string, null: false, default: "active"
      add :password_hash, :string
      add :profile, :map, null: false, default: %{}

      timestamps(type: :utc_datetime)
    end

    create unique_index(:users, [:email])
    create index(:users, [:status])
  end
end
