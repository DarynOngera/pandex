defmodule PandexWeb.BootstrapController do
  use PandexWeb, :controller

  alias Pandex.{Accounts, Security, Tenancy}
  alias Pandex.OAuth

  plug :ensure_bootstrap_enabled

  def create_tenant(conn, params) do
    with {:ok, tenant} <- Tenancy.create_tenant(params) do
      conn
      |> put_status(:created)
      |> json(%{tenant: tenant_json(tenant)})
    else
      {:error, changeset} -> render_changeset(conn, changeset)
    end
  end

  def create_user(conn, params) do
    with {:ok, user} <- Accounts.create_user(params) do
      conn
      |> put_status(:created)
      |> json(%{user: user_json(user)})
    else
      {:error, changeset} -> render_changeset(conn, changeset)
    end
  end

  def create_membership(conn, params) do
    with {:ok, membership} <- Tenancy.create_membership(params) do
      conn
      |> put_status(:created)
      |> json(%{membership: membership_json(membership)})
    else
      {:error, changeset} -> render_changeset(conn, changeset)
    end
  end

  def create_client(conn, params) do
    with {:ok, client} <- OAuth.create_client(params) do
      conn
      |> put_status(:created)
      |> json(%{client: client_json(client)})
    else
      {:error, changeset} -> render_changeset(conn, changeset)
    end
  end

  def create_signing_key(conn, params) do
    algorithm = Map.get(params, "algorithm", "RS256")

    with :ok <- validate_signing_algorithm(algorithm),
         {:ok, key} <- Security.rotate_signing_key(algorithm) do
      conn
      |> put_status(:created)
      |> json(%{signing_key: signing_key_json(key)})
    else
      {:error, :unsupported_algorithm} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "invalid_request", error_description: "unsupported signing algorithm"})
    end
  end

  defp validate_signing_algorithm("RS256"), do: :ok
  defp validate_signing_algorithm(_algorithm), do: {:error, :unsupported_algorithm}

  defp ensure_bootstrap_enabled(conn, _opts) do
    if Application.get_env(:pandex, :bootstrap_api_enabled, false) do
      conn
    else
      conn
      |> put_status(:not_found)
      |> json(%{error: "not_found"})
      |> halt()
    end
  end

  defp tenant_json(tenant) do
    %{
      id: tenant.id,
      name: tenant.name,
      slug: tenant.slug,
      status: tenant.status,
      settings: tenant.settings,
      branding: tenant.branding
    }
  end

  defp user_json(user) do
    %{
      id: user.id,
      email: user.email,
      status: user.status,
      profile: user.profile
    }
  end

  defp membership_json(membership) do
    %{
      id: membership.id,
      user_id: membership.user_id,
      tenant_id: membership.tenant_id,
      role: membership.role,
      status: membership.status
    }
  end

  defp client_json(client) do
    %{
      id: client.id,
      tenant_id: client.tenant_id,
      name: client.name,
      client_type: client.client_type,
      redirect_uris: client.redirect_uris,
      allowed_scopes: client.allowed_scopes,
      allowed_grants: client.allowed_grants,
      status: client.status,
      settings: client.settings
    }
  end

  defp signing_key_json(key) do
    %{
      id: key.id,
      kid: key.kid,
      algorithm: key.algorithm,
      status: key.status,
      public_key: key.public_key
    }
  end

  defp render_changeset(conn, changeset) do
    conn
    |> put_status(:unprocessable_entity)
    |> json(%{errors: changeset_errors(changeset)})
  end

  defp changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {message, opts} ->
      Regex.replace(~r"%{(\w+)}", message, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end
