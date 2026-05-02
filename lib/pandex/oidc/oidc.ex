defmodule Pandex.OIDC do
  @moduledoc """
  OIDC context — ID Token assembly, signing, and discovery metadata.

  This module composes claims from other contexts (Accounts, OAuth)
  and delegates all cryptographic operations to JOSE via the Security context.
  """
  alias Pandex.Security
  alias Pandex.Accounts.User
  alias Pandex.OIDC.DiscoveryCache

  # ── ID Token ──────────────────────────────────────────────────────────────────

  @doc """
  Build and sign a JWT ID Token for a given user and client.

  Follows OIDC Core §2 claim requirements:
    iss, sub, aud, exp, iat  — always present
    nonce                     — included when present in authorization code
    profile claims            — included when 'profile' scope was granted
  """
  def build_id_token(%User{} = user, client_id, opts \\ []) do
    with {:ok, signing_key} <- Security.get_active_signing_key() do
      now = System.system_time(:second)
      issuer = issuer_uri()
      nonce = opts[:nonce]

      claims =
        %{
          "iss" => issuer,
          "sub" => user.id,
          "aud" => client_id,
          "iat" => now,
          "exp" => now + 3600,
          "email" => user.email,
          "email_verified" => false
        }
        |> maybe_add_nonce(nonce)
        |> maybe_add_profile_claims(user, opts[:scopes] || [])

      sign_jwt(claims, signing_key)
    end
  end

  @doc "Verify and decode an ID Token JWT."
  def verify_id_token(token_string) do
    with {:ok, keys} <- Security.get_public_keys() do
      Enum.find_value(keys, {:error, :no_valid_key}, fn key ->
        try do
          jwk = JOSE.JWK.from_map(key.public_key)

          case JOSE.JWT.verify_strict(jwk, ["RS256", "ES256"], token_string) do
            {true, %JOSE.JWT{fields: claims}, _jws} -> {:ok, claims}
            _ -> nil
          end
        rescue
          _ -> nil
        end
      end)
    end
  end

  # ── UserInfo ──────────────────────────────────────────────────────────────────

  @doc "Build the UserInfo claim set for a given user and granted scopes."
  def build_userinfo(%User{} = user, scopes) do
    base = %{"sub" => user.id}

    base
    |> maybe_add_email_claim(user, scopes)
    |> maybe_add_profile_claims(user, scopes)
  end

  # ── Discovery ─────────────────────────────────────────────────────────────────

  @doc "Return the OIDC discovery metadata document."
  def discovery_metadata do
    case DiscoveryCache.get() do
      {:ok, meta} -> meta
      :miss -> build_and_cache_discovery()
    end
  end

  defp build_and_cache_discovery do
    issuer = issuer_uri()

    meta = %{
      "issuer" => issuer,
      "authorization_endpoint" => "#{issuer}/oauth/authorize",
      "token_endpoint" => "#{issuer}/oauth/token",
      "userinfo_endpoint" => "#{issuer}/oauth/userinfo",
      "jwks_uri" => "#{issuer}/.well-known/jwks.json",
      "revocation_endpoint" => "#{issuer}/oauth/revoke",
      "introspection_endpoint" => "#{issuer}/oauth/introspect",
      "response_types_supported" => ["code"],
      "grant_types_supported" => ["authorization_code", "refresh_token"],
      "subject_types_supported" => ["public"],
      "id_token_signing_alg_values_supported" => ["RS256", "ES256"],
      "scopes_supported" => ["openid", "profile", "email"],
      "token_endpoint_auth_methods_supported" => ["client_secret_post", "none"],
      "code_challenge_methods_supported" => ["S256"],
      "claims_supported" => [
        "sub",
        "iss",
        "aud",
        "exp",
        "iat",
        "email",
        "email_verified",
        "name",
        "given_name",
        "family_name"
      ]
    }

    DiscoveryCache.put(meta)
    meta
  end

  # ── Private helpers ───────────────────────────────────────────────────────────

  defp sign_jwt(claims, signing_key) do
    # In production, the private key material is retrieved from a KMS reference.
    # Here we stub this as: load the JWK stored at signing_key.private_key_ref.
    with {:ok, private_jwk} <- load_private_key(signing_key) do
      jws = %{"alg" => signing_key.algorithm, "kid" => signing_key.kid}

      {_type, token} =
        JOSE.JWT.sign(private_jwk, jws, claims)
        |> JOSE.JWS.compact()

      {:ok, token}
    end
  end

  defp load_private_key(%{private_key_ref: "local-jwk:" <> encoded_jwk}) do
    case Jason.decode(encoded_jwk) do
      {:ok, jwk} -> {:ok, JOSE.JWK.from_map(jwk)}
      {:error, reason} -> {:error, {:invalid_private_key_ref, reason}}
    end
  end

  # Replace this branch with KMS retrieval before production key material leaves the app DB.
  defp load_private_key(%{private_key_ref: ref}) when is_binary(ref) do
    {:error, {:kms_not_configured, ref}}
  end

  defp load_private_key(_), do: {:error, :no_private_key}

  defp issuer_uri, do: Application.fetch_env!(:pandex, :oidc_issuer)

  defp maybe_add_nonce(claims, nil), do: claims
  defp maybe_add_nonce(claims, nonce), do: Map.put(claims, "nonce", nonce)

  defp maybe_add_email_claim(claims, user, scopes) do
    if "email" in scopes do
      claims
      |> Map.put("email", user.email)
      |> Map.put("email_verified", false)
    else
      claims
    end
  end

  defp maybe_add_profile_claims(claims, user, scopes) do
    if "profile" in scopes do
      profile = user.profile || %{}

      Map.merge(
        claims,
        Map.take(profile, ["name", "given_name", "family_name", "picture", "locale"])
      )
    else
      claims
    end
  end
end
