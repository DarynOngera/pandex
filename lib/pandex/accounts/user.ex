defmodule Pandex.Accounts.User do
  @moduledoc "A person or service account that can authenticate."
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "users" do
    field :email, :string
    field :status, :string, default: "active"

    # Optional — only set for password-based accounts.
    # Passwordless-only flows leave this nil.
    field :password_hash, :string
    # Virtual — never persisted.
    field :password, :string, virtual: true

    # OIDC profile claims (JSONB)
    field :profile, :map, default: %{}

    has_many :memberships, Pandex.Tenancy.Membership
    has_many :sessions, Pandex.Sessions.Session
    has_many :login_challenges, Pandex.Sessions.LoginChallenge

    timestamps(type: :utc_datetime)
  end

  @doc "Changeset used during initial registration."
  def registration_changeset(user, attrs) do
    user
    |> cast(attrs, [:email, :password, :profile, :status])
    |> validate_required([:email])
    |> validate_format(:email, ~r/^[^\s]+@[^\s]+\.[^\s]+$/,
      message: "must be a valid email address"
    )
    |> validate_length(:email, max: 254)
    |> update_change(:email, &String.downcase/1)
    |> unique_constraint(:email)
    |> validate_inclusion(:status, ["active", "suspended", "deleted"])
    |> hash_password()
  end

  @doc "Changeset for profile updates — email / password not allowed here."
  def profile_changeset(user, attrs) do
    user
    |> cast(attrs, [:profile, :status])
    |> validate_inclusion(:status, ["active", "suspended", "deleted"])
  end

  # ── Private ───────────────────────────────────────────────────────────────────

  defp hash_password(changeset) do
    case get_change(changeset, :password) do
      nil ->
        changeset

      password ->
        changeset
        |> validate_length(:password, min: 12, max: 72)
        |> put_change(:password_hash, Bcrypt.hash_pwd_salt(password))
        |> delete_change(:password)
    end
  end
end
