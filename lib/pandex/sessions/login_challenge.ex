defmodule Pandex.Sessions.LoginChallenge do
  @moduledoc """
  A one-time login challenge — magic link, OTP, or passkey initiation.

  `code_hash` stores a BLAKE2b-256 digest; the raw code is returned
  once to the caller and must never be stored or logged.
  """
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "login_challenges" do
    belongs_to :user, Pandex.Accounts.User
    belongs_to :tenant, Pandex.Tenancy.Tenant

    field :type, :string
    field :code_hash, :string
    field :expires_at, :utc_datetime
    field :consumed_at, :utc_datetime

    timestamps(type: :utc_datetime)
  end

  @types ~w(magic_link otp passkey)

  def changeset(challenge, attrs) do
    challenge
    |> cast(attrs, [:user_id, :tenant_id, :type, :code_hash, :expires_at])
    |> validate_required([:user_id, :tenant_id, :type, :code_hash, :expires_at])
    |> validate_inclusion(:type, @types)
  end
end
