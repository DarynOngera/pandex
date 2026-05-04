defmodule Pandex.Security.KeyProvider do
  @moduledoc """
  Behaviour for private signing key retrieval.

  Implementations:
    - `Pandex.Security.KeyProvider.Local` — decodes a JWK stored in the DB.
      Suitable for development and test only.
    - (future) `Pandex.Security.KeyProvider.AwsKms` — retrieves key material
      from AWS KMS using the `private_key_ref` as the KMS key ARN.
    - (future) `Pandex.Security.KeyProvider.GcpKms` — same pattern for GCP.

  The active provider is configured per-environment:

      # config/dev.exs
      config :pandex, :key_provider, Pandex.Security.KeyProvider.Local

      # config/runtime.exs (production)
      config :pandex, :key_provider, Pandex.Security.KeyProvider.AwsKms

  All implementations must return `{:ok, %JOSE.JWK{}}` or `{:error, reason}`.
  The caller (`Pandex.OIDC`) is insulated from provider details — it only
  ever sees a `JOSE.JWK` struct ready for signing.
  """

  @doc """
  Load the private signing key identified by `private_key_ref`.

  `private_key_ref` is an opaque string whose format is provider-specific:
    - Local: `"local-jwk:<base64-encoded-JWK>"`
    - AWS KMS: `"arn:aws:kms:<region>:<account>:key/<key-id>"`
    - GCP KMS: `"projects/<project>/locations/<loc>/keyRings/<ring>/cryptoKeys/<key>"`
  """
  @callback load(private_key_ref :: String.t()) ::
              {:ok, JOSE.JWK.t()} | {:error, term()}

  @doc "Return the configured key provider module."
  def configured do
    Application.get_env(:pandex, :key_provider, Pandex.Security.KeyProvider.Local)
  end

  @doc "Delegate to the configured provider."
  def load(private_key_ref) do
    configured().load(private_key_ref)
  end
end
