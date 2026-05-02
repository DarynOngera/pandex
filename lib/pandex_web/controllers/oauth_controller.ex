defmodule PandexWeb.OAuthController do
  use PandexWeb, :controller

  alias Pandex.{Accounts, OAuth, Security, Sessions}
  alias Pandex.OAuth.Client

  def authorize(conn, params) do
    with :ok <- require_param(params, "client_id"),
         :ok <- require_param(params, "redirect_uri"),
         :ok <- require_param(params, "code_challenge"),
         :ok <- require_param(params, "session_id"),
         :ok <- validate_response_type(params),
         %Client{} = client <- OAuth.get_client(params["client_id"]),
         :ok <- validate_active_client(client),
         :ok <- OAuth.validate_redirect_uri(client, params["redirect_uri"]),
         scopes <- parse_scopes(params["scope"]),
         :ok <- OAuth.validate_scopes(client, scopes),
         :ok <- validate_code_challenge_method(params),
         session when not is_nil(session) <- Sessions.get_valid_session(params["session_id"]),
         :ok <- validate_session_client_boundary(session, client),
         {:ok, {raw_code, _code}} <-
           OAuth.issue_authorization_code(%{
             user_id: session.user_id,
             tenant_id: session.tenant_id,
             client_id: client.id,
             redirect_uri: params["redirect_uri"],
             scopes: scopes,
             code_challenge: params["code_challenge"],
             code_challenge_method: "S256",
             nonce: params["nonce"]
           }) do
      redirect(conn, external: redirect_uri(params["redirect_uri"], raw_code, params["state"]))
    else
      nil -> oauth_error(conn, :unauthorized, "invalid session or client")
      {:error, reason} -> handle_oauth_error(conn, reason)
    end
  end

  def token(conn, %{"grant_type" => "authorization_code"} = params) do
    with :ok <- require_param(params, "client_id"),
         :ok <- require_param(params, "code"),
         :ok <- require_param(params, "code_verifier"),
         %Client{} = client <- OAuth.get_client(params["client_id"]),
         :ok <- validate_active_client(client),
         :ok <- OAuth.authenticate_client(client, params["client_secret"]),
         {:ok, code} <-
           OAuth.exchange_authorization_code(
             params["code"],
             params["code_verifier"],
             client.id,
             params["redirect_uri"]
           ),
         user <- Accounts.get_user!(code.user_id),
         {:ok, {access_token, access}} <-
           OAuth.issue_access_token(%{
             user_id: code.user_id,
             tenant_id: code.tenant_id,
             client_id: code.client_id,
             scopes: code.scopes
           }),
         {:ok, {refresh_token, _refresh}} <-
           OAuth.issue_refresh_token(%{
             user_id: code.user_id,
             tenant_id: code.tenant_id,
             client_id: code.client_id,
             scopes: code.scopes
           }),
         {:ok, _key} <- Security.ensure_active_signing_key(),
         {:ok, id_token} <-
           Pandex.OIDC.build_id_token(user, client.id, nonce: code.nonce, scopes: code.scopes) do
      json(conn, %{
        access_token: access_token,
        token_type: "Bearer",
        expires_in: DateTime.diff(access.expires_at, DateTime.utc_now(), :second),
        refresh_token: refresh_token,
        id_token: id_token,
        scope: Enum.join(code.scopes, " ")
      })
    else
      nil -> oauth_error(conn, :unauthorized, "invalid client")
      {:error, reason} -> handle_oauth_error(conn, reason)
    end
  end

  def token(conn, %{"grant_type" => "refresh_token"} = params) do
    with :ok <- require_param(params, "client_id"),
         :ok <- require_param(params, "refresh_token"),
         %Client{} = client <- OAuth.get_client(params["client_id"]),
         :ok <- validate_active_client(client),
         :ok <- OAuth.authenticate_client(client, params["client_secret"]),
         {:ok, {refresh_token, refresh}} <-
           OAuth.rotate_refresh_token(params["refresh_token"], client.id),
         {:ok, {access_token, access}} <-
           OAuth.issue_access_token(%{
             user_id: refresh.user_id,
             tenant_id: refresh.tenant_id,
             client_id: refresh.client_id,
             scopes: refresh.scopes
           }) do
      json(conn, %{
        access_token: access_token,
        token_type: "Bearer",
        expires_in: DateTime.diff(access.expires_at, DateTime.utc_now(), :second),
        refresh_token: refresh_token,
        scope: Enum.join(refresh.scopes, " ")
      })
    else
      nil -> oauth_error(conn, :unauthorized, "invalid client")
      {:error, reason} -> handle_oauth_error(conn, reason)
    end
  end

  def token(conn, %{"grant_type" => _grant_type}) do
    oauth_error(conn, :bad_request, "unsupported grant type", "unsupported_grant_type")
  end

  def token(conn, _params), do: oauth_error(conn, :bad_request, "grant_type is required")

  def userinfo(conn, _params) do
    with {:ok, bearer} <- bearer_token(conn),
         {:ok, claims} <- OAuth.userinfo(bearer) do
      json(conn, claims)
    else
      {:error, :invalid_token} ->
        oauth_error(conn, :unauthorized, "invalid bearer token", "invalid_token")

      {:error, reason} ->
        handle_oauth_error(conn, reason)
    end
  end

  def introspect(conn, %{"token" => token} = params) do
    with :ok <- authenticate_introspection_client(params) do
      json(conn, OAuth.introspect(token))
    else
      {:error, reason} -> handle_oauth_error(conn, reason)
    end
  end

  def introspect(conn, _params), do: oauth_error(conn, :bad_request, "token is required")

  def revoke(conn, %{"token" => token} = params) do
    with :ok <- authenticate_introspection_client(params) do
      case params["token_type_hint"] do
        "access_token" -> OAuth.revoke_access_token(token)
        "refresh_token" -> OAuth.revoke_refresh_token(token)
        _ -> revoke_any(token)
      end

      send_resp(conn, 200, "")
    else
      {:error, reason} -> handle_oauth_error(conn, reason)
    end
  end

  def revoke(conn, _params), do: oauth_error(conn, :bad_request, "token is required")

  defp authenticate_introspection_client(%{"client_id" => client_id} = params) do
    case OAuth.get_client(client_id) do
      %Client{} = client ->
        with :ok <- validate_active_client(client) do
          OAuth.authenticate_client(client, params["client_secret"])
        end

      nil ->
        {:error, :invalid_client}
    end
  end

  defp authenticate_introspection_client(_params), do: {:error, :invalid_client}

  defp revoke_any(token) do
    OAuth.revoke_access_token(token)
    OAuth.revoke_refresh_token(token)
  end

  defp require_param(params, key) do
    case Map.get(params, key) do
      value when is_binary(value) and value != "" -> :ok
      _ -> {:error, {:missing_param, key}}
    end
  end

  defp validate_response_type(%{"response_type" => "code"}), do: :ok
  defp validate_response_type(_params), do: {:error, :unsupported_response_type}

  defp validate_active_client(%Client{status: "active"}), do: :ok
  defp validate_active_client(%Client{}), do: {:error, :invalid_client}

  defp validate_code_challenge_method(%{"code_challenge_method" => method}) when method != "S256",
    do: {:error, {:unsupported_pkce_method, method}}

  defp validate_code_challenge_method(_params), do: :ok

  defp validate_session_client_boundary(session, client) do
    if session.tenant_id == client.tenant_id, do: :ok, else: {:error, :invalid_grant}
  end

  defp parse_scopes(nil), do: ["openid"]

  defp parse_scopes(scope) do
    scope
    |> String.split(" ", trim: true)
    |> case do
      [] -> ["openid"]
      scopes -> scopes
    end
  end

  defp redirect_uri(uri, code, nil), do: redirect_uri(uri, code, "")

  defp redirect_uri(uri, code, state) do
    uri = URI.parse(uri)

    query =
      (uri.query || "")
      |> URI.decode_query()
      |> Map.put("code", code)

    query =
      if state == "" do
        query
      else
        Map.put(query, "state", state)
      end

    %{uri | query: URI.encode_query(query)}
    |> URI.to_string()
  end

  defp bearer_token(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token] -> {:ok, token}
      _ -> {:error, :invalid_token}
    end
  end

  defp handle_oauth_error(conn, {:missing_param, key}),
    do: oauth_error(conn, :bad_request, "missing required parameter: #{key}")

  defp handle_oauth_error(conn, :invalid_client),
    do: oauth_error(conn, :unauthorized, "client authentication failed", "invalid_client")

  defp handle_oauth_error(conn, :invalid_redirect_uri),
    do: oauth_error(conn, :bad_request, "redirect_uri is not registered")

  defp handle_oauth_error(conn, :invalid_scope),
    do: oauth_error(conn, :bad_request, "requested scope is not allowed", "invalid_scope")

  defp handle_oauth_error(conn, :invalid_code),
    do: oauth_error(conn, :bad_request, "authorization code is invalid", "invalid_grant")

  defp handle_oauth_error(conn, :invalid_grant),
    do: oauth_error(conn, :bad_request, "grant is invalid", "invalid_grant")

  defp handle_oauth_error(conn, :pkce_mismatch),
    do: oauth_error(conn, :bad_request, "PKCE verifier does not match challenge", "invalid_grant")

  defp handle_oauth_error(conn, :not_found),
    do: oauth_error(conn, :bad_request, "token not found", "invalid_grant")

  defp handle_oauth_error(conn, :revoked),
    do: oauth_error(conn, :bad_request, "token is revoked", "invalid_grant")

  defp handle_oauth_error(conn, :expired),
    do: oauth_error(conn, :bad_request, "token is expired", "invalid_grant")

  defp handle_oauth_error(conn, :reuse_detected),
    do: oauth_error(conn, :bad_request, "refresh token reuse detected", "invalid_grant")

  defp handle_oauth_error(conn, :unsupported_response_type),
    do: oauth_error(conn, :bad_request, "response_type must be code", "unsupported_response_type")

  defp handle_oauth_error(conn, {:unsupported_pkce_method, method}),
    do: oauth_error(conn, :bad_request, "unsupported PKCE method: #{method}", "invalid_request")

  defp handle_oauth_error(conn, %Ecto.Changeset{} = changeset) do
    conn
    |> put_status(:unprocessable_entity)
    |> json(%{errors: changeset_errors(changeset)})
  end

  defp handle_oauth_error(conn, reason),
    do: oauth_error(conn, :bad_request, inspect(reason))

  defp oauth_error(conn, status, description, error \\ "invalid_request") do
    conn
    |> put_status(status)
    |> json(%{error: error, error_description: description})
  end

  defp changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {message, opts} ->
      Regex.replace(~r"%{(\w+)}", message, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end
