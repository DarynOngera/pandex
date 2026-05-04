defmodule PandexWeb.SessionController do
  @moduledoc """
  Manages browser session cookies.

  Endpoints:
    POST /session     — Consume a login challenge and write the session cookie.
    DELETE /session   — Revoke the session and clear the cookie (logout).

  This is the browser-facing counterpart to the API `POST /login/challenges/consume`
  endpoint. The API endpoint returns `session_id` in JSON (for API clients);
  this endpoint sets the session cookie (for browser flows).

  Both paths call the same `Sessions.verify_and_consume_challenge/2` and
  `Sessions.create_session/1` context functions.
  """
  use PandexWeb, :controller

  alias Pandex.Sessions
  alias PandexWeb.Plugs.{RateLimit, SessionAuth}

  plug RateLimit, [bucket: "session_create", limit: 20, window_ms: 60_000] when action in [:create]

  def create(conn, %{"tenant_id" => tenant_id, "code" => code}) do
    with {:ok, challenge} <- Sessions.verify_and_consume_challenge(code, tenant_id),
         {:ok, session} <-
           Sessions.create_session(%{
             user_id: challenge.user_id,
             tenant_id: challenge.tenant_id,
             expires_at:
               DateTime.utc_now() |> DateTime.add(86_400, :second) |> DateTime.truncate(:second)
           }) do
      conn
      |> SessionAuth.put_session_cookie(session.id)
      |> json(%{
        session_id: session.id,
        user_id: session.user_id,
        tenant_id: session.tenant_id,
        expires_at: session.expires_at
      })
    else
      {:error, :invalid_or_expired} ->
        conn
        |> put_status(:unauthorized)
        |> json(%{error: "invalid_grant", error_description: "invalid or expired challenge"})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{errors: changeset_errors(changeset)})
    end
  end

  def create(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "invalid_request", error_description: "tenant_id and code are required"})
  end

  def delete(conn, _params) do
    case conn.assigns[:current_session] do
      nil ->
        conn
        |> SessionAuth.delete_session_cookie()
        |> send_resp(204, "")

      session ->
        Sessions.revoke_session(session)

        conn
        |> SessionAuth.delete_session_cookie()
        |> send_resp(204, "")
    end
  end

  defp changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {message, opts} ->
      Regex.replace(~r"%{(\w+)}", message, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end
