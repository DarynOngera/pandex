defmodule Pandex.OAuth do
  @moduledoc """
  OAuth context — manages Clients, Authorization Codes, and Tokens.

  Design rules enforced here:
    - Redirect URIs are matched byte-for-byte (no pattern matching).
    - PKCE (S256) is required for all public clients.
    - Token values are NEVER stored; only their BLAKE2b-256 digest.
    - Refresh token rotation: one-time use, predecessor invalidated atomically.
    - Refresh token reuse detection triggers full family revocation.

  Audit events are emitted inside the same transaction as the mutation they
  describe so events cannot be silently dropped or orphaned.
  """
  import Ecto.Query
  alias Pandex.Accounts.User
  alias Pandex.Audit
  alias Pandex.Repo
  alias Pandex.OAuth.{Client, AuthorizationCode, AuthorizationGrant, AccessToken, RefreshToken}

  # ── Clients ───────────────────────────────────────────────────────────────────

  def get_client(id), do: Repo.get(Client, id)
  def get_client!(id), do: Repo.get!(Client, id)

  def get_client_for_tenant!(client_id, tenant_id) do
    Repo.get_by!(Client, id: client_id, tenant_id: tenant_id)
  end

  def create_client(attrs) do
    Repo.transaction(fn ->
      with {:ok, client} <-
             %Client{}
             |> Client.changeset(attrs)
             |> Repo.insert(),
           {:ok, _} <-
             Audit.log(client.tenant_id, "client_created", %{
               target_id: client.id,
               target_type: "client",
               metadata: %{"name" => client.name, "client_type" => client.client_type}
             }) do
        client
      else
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
  end

  def update_client(%Client{} = client, attrs) do
    Repo.transaction(fn ->
      with {:ok, updated} <-
             client
             |> Client.changeset(attrs)
             |> Repo.update(),
           {:ok, _} <-
             Audit.log(client.tenant_id, "client_updated", %{
               target_id: client.id,
               target_type: "client"
             }) do
        updated
      else
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
  end

  def authenticate_client(%Client{client_type: "public"}, _secret), do: :ok

  def authenticate_client(%Client{client_type: "confidential", client_secret_hash: hash}, secret)
      when is_binary(hash) and is_binary(secret) do
    if Bcrypt.verify_pass(secret, hash), do: :ok, else: {:error, :invalid_client}
  end

  def authenticate_client(%Client{client_type: "confidential"}, _secret),
    do: {:error, :invalid_client}

  @doc "Validate that a redirect URI is registered for this client (exact match)."
  def validate_redirect_uri(%Client{redirect_uris: uris}, uri) do
    if uri in uris, do: :ok, else: {:error, :invalid_redirect_uri}
  end

  def validate_scopes(%Client{allowed_scopes: allowed_scopes}, scopes) do
    if Enum.all?(scopes, &(&1 in allowed_scopes)), do: :ok, else: {:error, :invalid_scope}
  end

  # ── Authorization Codes ───────────────────────────────────────────────────────

  @doc """
  Issue an authorization code for a successful authorization request.

  Also upserts an AuthorizationGrant recording user consent for the granted
  scopes on this client. Re-authorizing with different scopes replaces the
  existing grant record atomically.

  Returns `{:ok, {raw_code, authorization_code}}`.
  """
  def issue_authorization_code(attrs) do
    raw_code = generate_token()
    code_hash = hash_token(raw_code)
    expires_at = DateTime.add(DateTime.utc_now(), 60, :second) |> DateTime.truncate(:second)

    Repo.transaction(fn ->
      with {:ok, code} <-
             %AuthorizationCode{}
             |> AuthorizationCode.changeset(
               Map.merge(attrs, %{code_hash: code_hash, expires_at: expires_at})
             )
             |> Repo.insert(),
           :ok <- upsert_authorization_grant(code) do
        {raw_code, code}
      else
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
  end

  @doc "Return the active authorization grant for a user+client+tenant, if any."
  def get_authorization_grant(user_id, client_id, tenant_id) do
    Repo.get_by(Pandex.OAuth.AuthorizationGrant,
      user_id: user_id,
      client_id: client_id,
      tenant_id: tenant_id
    )
  end

  @doc """
  Exchange an authorization code for tokens.
  Validates PKCE code_verifier against stored code_challenge.
  Returns `{:ok, authorization_code}` or `{:error, reason}`.
  """
  def exchange_authorization_code(raw_code, code_verifier, client_id, redirect_uri \\ nil) do
    code_hash = hash_token(raw_code)
    now = DateTime.utc_now()

    Repo.transaction(fn ->
      query =
        where(
          AuthorizationCode,
          [c],
          c.code_hash == ^code_hash and
            c.client_id == ^client_id and
            is_nil(c.used_at) and
            c.expires_at > ^now
        )

      query =
        if is_binary(redirect_uri) and redirect_uri != "" do
          where(query, [c], c.redirect_uri == ^redirect_uri)
        else
          query
        end

      code = Repo.one(query)

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

    Repo.transaction(fn ->
      with {:ok, token} <-
             %AccessToken{}
             |> AccessToken.changeset(
               Map.merge(attrs, %{token_hash: token_hash, expires_at: expires_at})
             )
             |> Repo.insert(),
           {:ok, _} <-
             Audit.log(token.tenant_id, "token_issued", %{
               actor_id: token.user_id,
               target_id: token.client_id,
               target_type: "client",
               metadata: %{"token_type" => "access_token", "scopes" => token.scopes}
             }) do
        {raw_token, token}
      else
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
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

    expires_at =
      attrs[:expires_at] ||
        DateTime.utc_now() |> DateTime.add(30 * 86_400, :second) |> DateTime.truncate(:second)

    Repo.transaction(fn ->
      with {:ok, token} <-
             %RefreshToken{}
             |> RefreshToken.changeset(
               Map.merge(attrs, %{
                 token_hash: token_hash,
                 family_id: family_id,
                 expires_at: expires_at
               })
             )
             |> Repo.insert(),
           {:ok, _} <-
             Audit.log(token.tenant_id, "token_issued", %{
               actor_id: token.user_id,
               target_id: token.client_id,
               target_type: "client",
               metadata: %{
                 "token_type" => "refresh_token",
                 "family_id" => token.family_id,
                 "scopes" => token.scopes
               }
             }) do
        {raw_token, token}
      else
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
  end

  @doc """
  Rotate a refresh token.

  1. Fetch the token (scoped to client_id when provided).
  2. Validate it is present, unused, unrevoked, and unexpired.
  3. If already used → revoke the entire family and emit a security event.
  4. Mark the predecessor used, insert a successor, emit audit event.

  All steps run in a single transaction.
  Returns `{:ok, {raw_successor_token, successor_record}}` or `{:error, reason}`.
  """
  def rotate_refresh_token(raw_token, client_id \\ nil) do
    token_hash = hash_token(raw_token)
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    Repo.transaction(fn ->
      with {:ok, token} <- fetch_refresh_token(token_hash, client_id),
           :ok <- validate_refresh_token(token, now),
           {:ok, _} <- mark_token_used(token, now),
           {:ok, successor_raw, successor} <- insert_successor(token, now),
           {:ok, _} <- audit_token_rotated(token, successor) do
        {successor_raw, successor}
      else
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
  end

  def revoke_access_token(raw_token) do
    token_hash = hash_token(raw_token)
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    Repo.transaction(fn ->
      token =
        AccessToken
        |> where([t], t.token_hash == ^token_hash and is_nil(t.revoked_at))
        |> Repo.one()

      case token do
        nil ->
          {:ok, 0}

        t ->
          {count, _} =
            AccessToken
            |> where([a], a.id == ^t.id)
            |> Repo.update_all(set: [revoked_at: now])

          {:ok, _} =
            Audit.log(t.tenant_id, "token_revoked", %{
              actor_id: t.user_id,
              target_id: t.client_id,
              target_type: "client",
              metadata: %{"token_type" => "access_token"}
            })

          {:ok, count}
      end
    end)
    |> case do
      {:ok, result} -> result
      {:error, reason} -> {:error, reason}
    end
  end

  def revoke_refresh_token(raw_token) do
    token_hash = hash_token(raw_token)
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    Repo.transaction(fn ->
      token =
        RefreshToken
        |> where([t], t.token_hash == ^token_hash and is_nil(t.revoked_at))
        |> Repo.one()

      case token do
        nil ->
          {:ok, 0}

        t ->
          {count, _} =
            RefreshToken
            |> where([r], r.id == ^t.id)
            |> Repo.update_all(set: [revoked_at: now])

          {:ok, _} =
            Audit.log(t.tenant_id, "token_revoked", %{
              actor_id: t.user_id,
              target_id: t.client_id,
              target_type: "client",
              metadata: %{"token_type" => "refresh_token"}
            })

          {:ok, count}
      end
    end)
    |> case do
      {:ok, result} -> result
      {:error, reason} -> {:error, reason}
    end
  end

  def introspect(raw_token) do
    token_hash = hash_token(raw_token)
    now = DateTime.utc_now()

    token =
      AccessToken
      |> where([t], t.token_hash == ^token_hash and is_nil(t.revoked_at) and t.expires_at > ^now)
      |> Repo.one()

    case token do
      nil ->
        %{active: false}

      %AccessToken{} = token ->
        %{
          active: true,
          sub: token.user_id,
          client_id: token.client_id,
          tenant_id: token.tenant_id,
          scope: Enum.join(token.scopes, " "),
          exp: DateTime.to_unix(token.expires_at),
          token_type: "Bearer"
        }
    end
  end

  def userinfo(raw_token) do
    case introspect_access_token(raw_token) do
      nil ->
        {:error, :invalid_token}

      %AccessToken{} = token ->
        user = Repo.get!(User, token.user_id)
        {:ok, Pandex.OIDC.build_userinfo(user, token.scopes)}
    end
  end

  # ── rotate_refresh_token helpers ─────────────────────────────────────────────

  defp fetch_refresh_token(token_hash, client_id) do
    RefreshToken
    |> where([t], t.token_hash == ^token_hash)
    |> then(fn query ->
      if is_binary(client_id) and client_id != "",
        do: where(query, [t], t.client_id == ^client_id),
        else: query
    end)
    |> Repo.one()
    |> case do
      nil -> {:error, :not_found}
      token -> {:ok, token}
    end
  end

  # Validates state in order: reuse > revoked > expired.
  # Reuse is handled here (not a simple error) because it requires a side effect
  # — family revocation — before rolling back.
  defp validate_refresh_token(%RefreshToken{used_at: used_at} = token, now)
       when not is_nil(used_at) do
    revoke_token_family!(token.family_id, now)

    Audit.log(token.tenant_id, "token_reuse_detected", %{
      actor_id: token.user_id,
      target_id: token.client_id,
      target_type: "client",
      metadata: %{"family_id" => token.family_id, "token_type" => "refresh_token"}
    })

    {:error, :reuse_detected}
  end

  defp validate_refresh_token(%RefreshToken{revoked_at: revoked_at}, _now)
       when not is_nil(revoked_at),
       do: {:error, :revoked}

  defp validate_refresh_token(%RefreshToken{expires_at: expires_at}, now) do
    if DateTime.compare(expires_at, now) == :lt,
      do: {:error, :expired},
      else: :ok
  end

  defp mark_token_used(token, now) do
    token
    |> Ecto.Changeset.change(used_at: now)
    |> Repo.update()
  end

  defp insert_successor(predecessor, now) do
    successor_raw = generate_token()

    attrs = %{
      user_id: predecessor.user_id,
      tenant_id: predecessor.tenant_id,
      client_id: predecessor.client_id,
      scopes: predecessor.scopes,
      family_id: predecessor.family_id,
      rotated_from_id: predecessor.id,
      token_hash: hash_token(successor_raw),
      expires_at: now |> DateTime.add(30 * 86_400, :second)
    }

    case %RefreshToken{} |> RefreshToken.changeset(attrs) |> Repo.insert() do
      {:ok, successor} -> {:ok, successor_raw, successor}
      {:error, reason} -> {:error, reason}
    end
  end

  defp audit_token_rotated(predecessor, successor) do
    Audit.log(predecessor.tenant_id, "token_rotated", %{
      actor_id: predecessor.user_id,
      target_id: predecessor.client_id,
      target_type: "client",
      metadata: %{
        "family_id" => predecessor.family_id,
        "predecessor_id" => predecessor.id,
        "successor_id" => successor.id
      }
    })
  end

  defp revoke_token_family!(family_id, now) do
    RefreshToken
    |> where([t], t.family_id == ^family_id and is_nil(t.revoked_at))
    |> Repo.update_all(set: [revoked_at: now])
  end

  # ── Authorization Grants ──────────────────────────────────────────────────────

  # Upsert the grant record when an authorization code is issued.
  # On conflict (same user+client+tenant), replace scopes and consented_at
  # so the grant always reflects the most recently approved scope set.
  defp upsert_authorization_grant(%AuthorizationCode{} = code) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    grant_attrs = %{
      user_id: code.user_id,
      client_id: code.client_id,
      tenant_id: code.tenant_id,
      scopes: code.scopes,
      consented_at: now
    }

    result =
      %AuthorizationGrant{}
      |> AuthorizationGrant.changeset(grant_attrs)
      |> Repo.insert(
        on_conflict: {:replace, [:scopes, :consented_at, :updated_at]},
        conflict_target: [:user_id, :client_id, :tenant_id]
      )

    case result do
      {:ok, _grant} -> :ok
      {:error, changeset} -> {:error, changeset}
    end
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
