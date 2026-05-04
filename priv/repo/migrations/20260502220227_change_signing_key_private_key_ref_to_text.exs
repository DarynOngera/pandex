defmodule Pandex.Repo.Migrations.ChangeSigningKeyPrivateKeyRefToText do
  use Ecto.Migration

  def change do
    alter table(:signing_keys) do
      modify :private_key_ref, :text
    end
  end
end
