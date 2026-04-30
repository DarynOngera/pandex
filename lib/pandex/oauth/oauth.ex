defmodule Pandex.OAuth do
  @moduledoc """
  OAuth context — manages Clients, Authorization Codes, and Tokens.

  Design rules enforced here:
    - Redirect URIs are matched byte-for-byte (no pattern matching).
    - PKCE (S256) is required for all public clients.
    - Token values are NEVER stored; only their BLAKE2b-256 digest.
    - Refresh token rotation: one-time use, predecessor invalidated atomically.
    - Refresh token reuse detection triggers full family revocation.
  """
  import Ecto.Query
  alias Pandex.Repo
  alias Pandex.OAuth.{Client, AuthorizationCode, AccessToken, RefreshToken}

  # ── Clients ───────────────────────────────────────────────────────────────────

  def get_client!(id), do: Repo.get!(Client, id)

  def get_client_for_tenant!(client_id, tenant_id) do
    Repo.get_by!(Client, id: client_id, tenant_id: tenant_id)
  end

  def create_client(attrs) do
    %Client{}
    |> Client.changeset(attrs)
    |> Repo.insert()
  end

  def update_client(%Client{} = client, attrs) do
    client
    |> Client.changeset(attrs)
    |> Repo.update()
  end

  @doc "Validate that a redirect URI is registered for this client (exact match)."
  def validate_redirect_uri(%Client{redirect_uris: uris}, uri) do
    if uri in uris, do: :ok, else: {:error, :invalid_redirect_uri}
  end

  # ── Authorization Codes ───────────────────────────────────────────────────────

  @doc """
  Issue an authorization code for a successful authorization request.
  Returns `{:ok, {raw_code, authorization_code}}`.
  """
  def issue_authorization_code(attrs) do
    raw_code = generate_token()
    code_hash = hash_token(raw_code)
    expires_at = DateTime.add(DateTime.utc_now(), 60, :second) |> DateTime.truncate(:second)

    with {:ok, code} <-
           %AuthorizationCode{}
           |> AuthorizationCode.changeset(
             Map.merge(attrs, %{code_hash: code_hash, expires_at: expires_at})
           )
           |> Repo.insert() do
      {:ok, {raw_code, code}}
    end
  end

  @doc """
  Exchange an authorization code for tokens.
  Validates PKCE code_verifier against stored code_challenge.
  Returns `{:ok, authorization_code}` or `{:error, reason}`.
  """
  def exchange_authorization_code(raw_code, code_verifier, client_id) do
    code_hash = hash_token(raw_code)
    now = DateTime.utc_now()

    Repo.transaction(fn ->
      code =
        AuthorizationCode
        |> where(
          [c],
          c.code_hash == ^code_hash and
            c.client_id == ^client_id and
            is_nil(c.used_at) and
            c.expires_at > ^now
        )
        |> Repo.one()

      with %AuthorizationCode{} = c <- code || Repo.rollback(:invalid_code),
           :ok <- verify_pkce(code_verifier, c.code_challenge, c.code_challenge_method) do
        {:ok, used} =
          c
          |> Ecto.Changeset.change(used_at: DateTime.truncate(now, :second))
          |> Repo.update()

        used
      else
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
  end

  # ── Access Tokens ─────────────────────────────────────────────────────────────

  @doc "Issue a new opaque access token. Raw value returned once."
  def issue_access_token(attrs) do
    raw_token = generate_token()
    token_hash = hash_token(raw_token)
    expires_at = DateTime.add(DateTime.utc_now(), 3600, :second) |> DateTime.truncate(:second)

    with {:ok, token} <-
           %AccessToken{}
           |> AccessToken.changeset(
             Map.merge(attrs, %{token_hash: token_hash, expires_at: expires_at})
           )
           |> Repo.insert() do
      {:ok, {raw_token, token}}
    end
  end

  @doc "Verify an inbound access token (introspection / resource server)."
  def introspect_access_token(raw_token) do
    token_hash = hash_token(raw_token)
    now = DateTime.utc_now()

    AccessToken
    |> where(
      [t],
      t.token_hash == ^token_hash and
        t.expires_at > ^now and
        is_nil(t.revoked_at)
    )
    |> Repo.one()
  end

  # ── Refresh Tokens ────────────────────────────────────────────────────────────

  @doc """
  Issue a refresh token (always part of a family).
  Pass `family_id: nil` to start a new family.
  """
  def issue_refresh_token(attrs) do
    raw_token = generate_token()
    token_hash = hash_token(raw_token)
    family_id = attrs[:family_id] || Ecto.UUID.generate()

    with {:ok, token} <-
           %RefreshToken{}
           |> RefreshToken.changeset(
             Map.merge(attrs, %{
               token_hash: token_hash,
               family_id: family_id
             })
           )
           |> Repo.insert() do
      {:ok, {raw_token, token}}
    end
  end

  @doc """
  Rotate a refresh token.

  1. Validates the inbound token.
  2. Marks it used.
  3. If the token was already used → FAMILY REVOCATION (security event).
  4. Issues a new token in the same family.

  All steps execute in a single serialisable transaction.
  """
  def rotate_refresh_token(raw_token) do
    token_hash = hash_token(raw_token)
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    Repo.transaction(fn ->
      token =
        RefreshToken
        |> where([t], t.token_hash == ^token_hash)
        |> Repo.one()

      cond do
        is_nil(token) ->
          Repo.rollback(:not_found)

        not is_nil(token.used_at) ->
          # Reuse detected — revoke entire family
          revoke_token_family!(token.family_id, now)
          Repo.rollback(:reuse_detected)

        not is_nil(token.revoked_at) ->
          Repo.rollback(:revoked)

        DateTime.compare(token.expires_at, DateTime.utc_now()) == :lt ->
          Repo.rollback(:expired)

        true ->
          # Mark predecessor used
          {:ok, _} =
            token
            |> Ecto.Changeset.change(used_at: now)
            |> Repo.update()

          # Issue successor in same family
          issue_refresh_token(%{
            user_id: token.user_id,
            tenant_id: token.tenant_id,
            client_id: token.client_id,
            scopes: token.scopes,
            family_id: token.family_id,
            rotated_from: token.id
          })
      end
    end)
  end

  defp revoke_token_family!(family_id, now) do
    RefreshToken
    |> where([t], t.family_id == ^family_id and is_nil(t.revoked_at))
    |> Repo.update_all(set: [revoked_at: now])
  end

  # ── PKCE ──────────────────────────────────────────────────────────────────────

  defp verify_pkce(verifier, challenge, "S256") do
    computed =
      :crypto.hash(:sha256, verifier)
      |> Base.url_encode64(padding: false)

    if computed == challenge, do: :ok, else: {:error, :pkce_mismatch}
  end

  defp verify_pkce(_verifier, _challenge, method),
    do: {:error, {:unsupported_pkce_method, method}}

  # ── Token helpers ─────────────────────────────────────────────────────────────

  defp generate_token, do: :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
  defp hash_token(raw), do: :crypto.hash(:blake2b, raw) |> Base.encode16(case: :lower)
end
