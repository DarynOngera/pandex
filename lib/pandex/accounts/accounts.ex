defmodule Pandex.Accounts do
  @moduledoc """
  Accounts context — manages Users.

  Users exist globally; their membership in a Tenant is tracked via
  Pandex.Tenancy.Membership. This separation keeps the user pool
  clean and avoids duplicate records when a user joins multiple tenants.

  Audit events are emitted inside the same transaction as the mutation.
  Because users are global (no tenant_id), audit events for user mutations
  use the sentinel tenant_id "00000000-0000-0000-0000-000000000000" to
  satisfy the schema constraint while making the scope clear.
  """
  import Ecto.Query
  alias Pandex.Audit
  alias Pandex.Repo
  alias Pandex.Accounts.User

  @system_tenant_id "00000000-0000-0000-0000-000000000000"

  def get_user!(id), do: Repo.get!(User, id)

  def get_user_by_email(email) when is_binary(email) do
    Repo.get_by(User, email: String.downcase(email))
  end

  @doc """
  Fetches a user by email AND confirms membership in the given tenant.
  Returns `{:ok, user}` or `{:error, :not_found}`.
  """
  def get_user_for_tenant(email, tenant_id) do
    user =
      User
      |> join(:inner, [u], m in Pandex.Tenancy.Membership,
        on: m.user_id == u.id and m.tenant_id == ^tenant_id and m.status == "active"
      )
      |> where([u], u.email == ^String.downcase(email) and u.status == "active")
      |> Repo.one()

    case user do
      nil -> {:error, :not_found}
      user -> {:ok, user}
    end
  end

  def create_user(attrs \\ %{}) do
    Repo.transaction(fn ->
      with {:ok, user} <-
             %User{}
             |> User.registration_changeset(attrs)
             |> Repo.insert(),
           {:ok, _} <-
             Audit.log(@system_tenant_id, "user_created", %{
               actor_id: user.id,
               target_id: user.id,
               target_type: "user",
               metadata: %{"email" => user.email}
             }) do
        user
      else
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
  end

  def update_user(%User{} = user, attrs) do
    user
    |> User.profile_changeset(attrs)
    |> Repo.update()
  end

  def suspend_user(%User{} = user) do
    Repo.transaction(fn ->
      with {:ok, suspended} <-
             user
             |> Ecto.Changeset.change(status: "suspended")
             |> Repo.update(),
           {:ok, _} <-
             Audit.log(@system_tenant_id, "user_suspended", %{
               target_id: user.id,
               target_type: "user"
             }) do
        suspended
      else
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
  end
end
