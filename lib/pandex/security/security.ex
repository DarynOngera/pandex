defmodule Pandex.Security do
  @moduledoc """
  Security context — manages cryptographic signing keys.

  The active signing key is used for new ID Token signatures.
  The previous key is kept in JWKS for a grace period so relying parties
  can verify tokens signed before rotation.
  """
  alias Pandex.Repo
  alias Pandex.Security.{SigningKey, KeyCache}

  # ── Key queries ───────────────────────────────────────────────────────────────

  @doc "Return the currently active signing key (from ETS cache, fallback DB)."
  def get_active_signing_key do
    case KeyCache.get_active() do
      {:ok, key} -> {:ok, key}
      :miss -> load_and_cache_active_key()
    end
  end

  @doc "Return all public keys for JWKS publication."
  def get_public_keys do
    case KeyCache.get_jwks() do
      {:ok, keys} -> {:ok, keys}
      :miss -> load_and_cache_jwks()
    end
  end

  # ── Key rotation ──────────────────────────────────────────────────────────────

  @doc """
  Rotate signing keys.

  1. Demote current active key → previous.
  2. Mark any existing previous key → retired.
  3. Generate a fresh key pair → active.
  4. Invalidate ETS cache (PubSub broadcast).
  """
  def rotate_signing_key(algorithm \\ "RS256") do
    Repo.transaction(fn ->
      # Demote active → previous
      from_active_to_previous()

      # Generate and persist new key
      {:ok, new_key} = generate_and_insert_key(algorithm)
      new_key
    end)
    |> tap(fn _ -> KeyCache.invalidate() end)
  end

  def ensure_active_signing_key(algorithm \\ "RS256") do
    case get_active_signing_key() do
      {:ok, key} -> {:ok, key}
      {:error, :no_active_signing_key} -> rotate_signing_key(algorithm)
    end
  end

  # ── Private ───────────────────────────────────────────────────────────────────

  import Ecto.Query

  defp from_active_to_previous do
    SigningKey
    |> where([k], k.status == "previous")
    |> Repo.update_all(set: [status: "retired"])

    SigningKey
    |> where([k], k.status == "active")
    |> Repo.update_all(set: [status: "previous"])
  end

  defp generate_and_insert_key("RS256") do
    # Generate RSA-2048 key pair via JOSE
    {_public_jwk, private_jwk} = JOSE.JWK.generate_key({:rsa, 2048}) |> JOSE.JWK.to_map()
    kid = :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)

    attrs = %{
      kid: kid,
      algorithm: "RS256",
      status: "active",
      public_key: Map.take(private_jwk, ["kty", "n", "e"]),
      private_key_ref: encode_local_private_key(private_jwk)
    }

    %SigningKey{}
    |> SigningKey.changeset(attrs)
    |> Repo.insert()
  end

  defp encode_local_private_key(private_jwk) do
    "local-jwk:" <> Jason.encode!(private_jwk)
  end

  defp load_and_cache_active_key do
    key = SigningKey |> where([k], k.status == "active") |> Repo.one()

    case key do
      nil ->
        {:error, :no_active_signing_key}

      k ->
        KeyCache.put_active(k)
        {:ok, k}
    end
  end

  defp load_and_cache_jwks do
    keys =
      SigningKey
      |> where([k], k.status in ["active", "previous"])
      |> Repo.all()

    KeyCache.put_jwks(keys)
    {:ok, keys}
  end
end
