defmodule PandexWeb.Plugs.SessionAuth do
  @moduledoc """
  Plug that loads the current authenticated session from the signed cookie.

  The cookie key is `pandex_session_id`. On successful load, the session
  struct is assigned to `conn.assigns.current_session` and the user to
  `conn.assigns.current_user`.

  Behaviour by option:
    - `required: true`  (default) — halts with 401 JSON if no valid session.
    - `required: false` — assigns nil and continues; use when a route should
      work for both authenticated and anonymous users.

  Cookie is set by `PandexWeb.SessionController.create/2` after a successful
  challenge consume. It is HttpOnly, SameSite=Lax, and Secure in production.

  The `session_id` query parameter is also accepted as a fallback for
  API-style clients and existing tests. Cookie takes precedence when present.
  """
  import Plug.Conn
  import Phoenix.Controller, only: [json: 2]

  alias Pandex.{Accounts, Sessions}

  @cookie_key "pandex_session_id"

  def init(opts), do: %{required: Keyword.get(opts, :required, true)}

  def call(conn, %{required: required}) do
    session_id = resolve_session_id(conn)

    case load_session(session_id) do
      {:ok, session, user} ->
        conn
        |> assign(:current_session, session)
        |> assign(:current_user, user)

      :error when required ->
        conn
        |> put_status(:unauthorized)
        |> json(%{error: "unauthorized", error_description: "valid session required"})
        |> halt()

      :error ->
        conn
        |> assign(:current_session, nil)
        |> assign(:current_user, nil)
    end
  end

  @doc """
  Write the session cookie onto `conn`.

  Called by the session creation flow after a successful challenge consume.
  """
  def put_session_cookie(conn, session_id) do
    max_age = 86_400

    opts =
      [
        http_only: true,
        same_site: "Lax",
        max_age: max_age
      ]
      |> then(fn o ->
        if secure_cookies?(), do: Keyword.put(o, :secure, true), else: o
      end)

    put_resp_cookie(conn, @cookie_key, session_id, opts)
  end

  @doc "Delete the session cookie (logout)."
  def delete_session_cookie(conn) do
    delete_resp_cookie(conn, @cookie_key)
  end

  # ── Private ───────────────────────────────────────────────────────────────────

  # Cookie takes precedence over the query param so browser flows always win.
  defp resolve_session_id(conn) do
    case conn.req_cookies[@cookie_key] do
      nil -> conn.params["session_id"]
      cookie_val -> cookie_val
    end
  end

  defp load_session(nil), do: :error

  defp load_session(session_id) do
    case Sessions.get_valid_session(session_id) do
      nil ->
        :error

      session ->
        user = Accounts.get_user!(session.user_id)
        {:ok, session, user}
    end
  end

  defp secure_cookies? do
    Application.get_env(:pandex, :secure_cookies, false)
  end
end
