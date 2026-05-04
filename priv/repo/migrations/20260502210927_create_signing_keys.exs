defmodule Pandex.Repo.Migrations.CreateSigningKeys do
  use Ecto.Migration

  def change do
    create table(:signing_keys, primary_key: false) do
      add :id, :binary_id, primary_key: true, null: false
      add :kid, :string, null: false
      add :algorithm, :string, null: false
      add :status, :string, null: false, default: "active"
      add :public_key, :map, null: false
      add :private_key_ref, :string

      timestamps(type: :utc_datetime)
    end

    create unique_index(:signing_keys, [:kid])
    create index(:signing_keys, [:status])
  end
end
