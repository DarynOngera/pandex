defmodule PandexWeb.LoginController do
  use PandexWeb, :controller

  require Logger

  alias Pandex.{Accounts, Emails.LoginEmail, Mailer, Sessions}
  alias PandexWeb.Plugs.RateLimit

  # 10 challenge requests per IP per minute — tight because this is the
  # primary user-enumeration and spam surface.
  plug RateLimit, bucket: "login_challenge", limit: 10, window_ms: 60_000
  # Consume is per-IP, slightly looser — covers retries from a single session.
  plug RateLimit, bucket: "login_consume", limit: 20, window_ms: 60_000

  def create_challenge(conn, %{"tenant_id" => tenant_id, "email" => email} = params) do
    with {:ok, type} <- challenge_type(Map.get(params, "type", "magic_link")),
         {:ok, user} <- Accounts.get_user_for_tenant(email, tenant_id),
         {:ok, {raw_code, challenge}} <- Sessions.create_login_challenge(user.id, tenant_id, type) do
      deliver_challenge_email(type, user.email, tenant_id, raw_code)

      body = %{
        challenge_id: challenge.id,
        tenant_id: challenge.tenant_id,
        type: challenge.type,
        expires_at: challenge.expires_at
      }

      body =
        if Application.get_env(:pandex, :expose_login_challenge_codes, false) do
          Map.put(body, :code, raw_code)
        else
          body
        end

      conn
      |> put_status(:created)
      |> json(body)
    else
      {:error, :not_found} ->
        # Return the same shape as success to avoid user enumeration.
        # The client cannot distinguish "user not found" from "email sent".
        conn
        |> put_status(:created)
        |> json(%{status: "challenge_issued"})

      {:error, :unsupported_challenge_type} ->
        oauth_error(conn, :bad_request, "unsupported challenge type")

      {:error, changeset} ->
        render_changeset(conn, changeset)
    end
  end

  def create_challenge(conn, _params),
    do: oauth_error(conn, :bad_request, "tenant_id and email are required")

  def consume_challenge(conn, %{"tenant_id" => tenant_id, "code" => code}) do
    with {:ok, challenge} <- Sessions.verify_and_consume_challenge(code, tenant_id),
         {:ok, session} <-
           Sessions.create_session(%{
             user_id: challenge.user_id,
             tenant_id: challenge.tenant_id,
             expires_at:
               DateTime.utc_now() |> DateTime.add(86_400, :second) |> DateTime.truncate(:second)
           }) do
      json(conn, %{
        session_id: session.id,
        user_id: session.user_id,
        tenant_id: session.tenant_id,
        expires_at: session.expires_at
      })
    else
      {:error, :invalid_or_expired} ->
        oauth_error(conn, :unauthorized, "invalid or expired challenge")

      {:error, changeset} ->
        render_changeset(conn, changeset)
    end
  end

  def consume_challenge(conn, _params),
    do: oauth_error(conn, :bad_request, "tenant_id and code are required")

  # ── Private ───────────────────────────────────────────────────────────────────

  # Deliver email and swallow delivery errors — the challenge DB record is
  # already committed. Log failures so ops can investigate without blocking
  # the caller. A production setup would use a job queue (Oban etc.) here.
  defp deliver_challenge_email(:magic_link, to_email, tenant_id, raw_code) do
    email = LoginEmail.magic_link(to_email, tenant_id, raw_code)

    case Mailer.deliver(email) do
      {:ok, _} ->
        :ok

      {:error, reason} ->
        Logger.error("Failed to deliver magic link email to #{to_email}: #{inspect(reason)}")
        :ok
    end
  end

  defp deliver_challenge_email(:otp, to_email, _tenant_id, raw_code) do
    email = LoginEmail.otp(to_email, raw_code)

    case Mailer.deliver(email) do
      {:ok, _} ->
        :ok

      {:error, reason} ->
        Logger.error("Failed to deliver OTP email to #{to_email}: #{inspect(reason)}")
        :ok
    end
  end

  # Passkey challenges don't use email delivery.
  defp deliver_challenge_email(:passkey, _to_email, _tenant_id, _raw_code), do: :ok

  defp challenge_type("magic_link"), do: {:ok, :magic_link}
  defp challenge_type("otp"), do: {:ok, :otp}
  defp challenge_type("passkey"), do: {:ok, :passkey}
  defp challenge_type(_type), do: {:error, :unsupported_challenge_type}

  defp oauth_error(conn, status, description) do
    conn
    |> put_status(status)
    |> json(%{error: error_name(status), error_description: description})
  end

  defp error_name(:bad_request), do: "invalid_request"
  defp error_name(:unauthorized), do: "invalid_token"
  defp error_name(:not_found), do: "not_found"
  defp error_name(_status), do: "request_failed"

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
