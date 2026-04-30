defmodule Pandex.Sessions do
  @moduledoc """
  Sessions context — manages browser sessions and login challenges
  (magic links / OTP codes).

  Raw challenge codes are NEVER stored; only their BLAKE2b hash is persisted.
  """
  import Ecto.Query
  alias Pandex.Repo
  alias Pandex.Sessions.{Session, LoginChallenge}

  # ── Sessions ──────────────────────────────────────────────────────────────────

  @doc "Create a new session after successful authentication."
  def create_session(attrs \\ %{}) do
    %Session{}
    |> Session.changeset(attrs)
    |> Repo.insert()
  end

  @doc "Fetch a valid (non-expired) session by id."
  def get_valid_session(id) do
    now = DateTime.utc_now()

    Session
    |> where([s], s.id == ^id and s.expires_at > ^now and is_nil(s.revoked_at))
    |> Repo.one()
  end

  @doc "Revoke a session immediately (logout)."
  def revoke_session(%Session{} = session) do
    session
    |> Ecto.Changeset.change(revoked_at: DateTime.utc_now() |> DateTime.truncate(:second))
    |> Repo.update()
  end

  @doc "Revoke all sessions for a user in a tenant (e.g. password change)."
  def revoke_all_sessions(user_id, tenant_id) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    {count, _} =
      Session
      |> where([s], s.user_id == ^user_id and s.tenant_id == ^tenant_id and is_nil(s.revoked_at))
      |> Repo.update_all(set: [revoked_at: now])

    {:ok, count}
  end

  # ── Login Challenges ──────────────────────────────────────────────────────────

  @doc """
  Issue a new login challenge (magic link / OTP).

  Returns `{:ok, {raw_code, challenge}}`.
  The `raw_code` must be delivered to the user (email / SMS) and is NEVER stored.
  """
  def create_login_challenge(user_id, tenant_id, type \\ :magic_link) do
    raw_code = generate_secure_code()
    code_hash = hash_code(raw_code)
    expires_at = DateTime.add(DateTime.utc_now(), 15 * 60, :second) |> DateTime.truncate(:second)

    attrs = %{
      user_id: user_id,
      tenant_id: tenant_id,
      type: Atom.to_string(type),
      code_hash: code_hash,
      expires_at: expires_at
    }

    with {:ok, challenge} <- %LoginChallenge{} |> LoginChallenge.changeset(attrs) |> Repo.insert() do
      {:ok, {raw_code, challenge}}
    end
  end

  @doc """
  Verify and consume a login challenge.

  Returns `{:ok, challenge}` on success, or `{:error, reason}`.
  Consumed challenges are marked immediately — replay attacks are blocked.
  """
  def verify_and_consume_challenge(raw_code, tenant_id) do
    code_hash = hash_code(raw_code)
    now = DateTime.utc_now()

    Repo.transaction(fn ->
      challenge =
        LoginChallenge
        |> where(
          [c],
          c.code_hash == ^code_hash and
            c.tenant_id == ^tenant_id and
            is_nil(c.consumed_at) and
            c.expires_at > ^now
        )
        |> Repo.one()

      case challenge do
        nil ->
          Repo.rollback(:invalid_or_expired)

        ch ->
          {:ok, consumed} =
            ch
            |> Ecto.Changeset.change(consumed_at: DateTime.truncate(now, :second))
            |> Repo.update()

          consumed
      end
    end)
  end

  # ── Private ───────────────────────────────────────────────────────────────────

  # 32 bytes of CSPRNG → hex string (64 chars)
  defp generate_secure_code, do: :crypto.strong_rand_bytes(32) |> Base.encode16(case: :lower)

  # BLAKE2b-256 digest
  defp hash_code(raw), do: :crypto.hash(:blake2b, raw) |> Base.encode16(case: :lower)
end
