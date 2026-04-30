defmodule Pandex.Tenancy do
  @moduledoc """
  Tenancy context — manages Tenants and Memberships.

  Every operation that touches tenant-scoped data MUST receive an explicit
  `%Tenant{}` or `tenant_id` to prevent cross-tenant leakage.
  """
  import Ecto.Query
  alias Pandex.Repo
  alias Pandex.Tenancy.{Tenant, Membership}

  # ── Tenants ──────────────────────────────────────────────────────────────────

  @doc "List all tenants (super-admin only)."
  def list_tenants, do: Repo.all(Tenant)

  @doc "Fetch a tenant by id."
  def get_tenant!(id), do: Repo.get!(Tenant, id)

  @doc "Fetch a tenant by slug."
  def get_tenant_by_slug(slug), do: Repo.get_by(Tenant, slug: slug)

  @doc "Create a new tenant."
  def create_tenant(attrs \\ %{}) do
    %Tenant{}
    |> Tenant.changeset(attrs)
    |> Repo.insert()
  end

  @doc "Update a tenant's settings / branding."
  def update_tenant(%Tenant{} = tenant, attrs) do
    tenant
    |> Tenant.changeset(attrs)
    |> Repo.update()
  end

  # ── Memberships ───────────────────────────────────────────────────────────────

  @doc "Add a user to a tenant."
  def create_membership(attrs \\ %{}) do
    %Membership{}
    |> Membership.changeset(attrs)
    |> Repo.insert()
  end

  @doc "Find a membership, enforcing tenant boundary."
  def get_membership(tenant_id, user_id) do
    Repo.get_by(Membership, tenant_id: tenant_id, user_id: user_id)
  end

  @doc "List all members of a tenant."
  def list_memberships(%Tenant{id: tenant_id}) do
    Membership
    |> where([m], m.tenant_id == ^tenant_id)
    |> Repo.all()
  end

  @doc "Update a membership (role / status)."
  def update_membership(%Membership{} = membership, attrs) do
    membership
    |> Membership.changeset(attrs)
    |> Repo.update()
  end
end
