defmodule PandexWeb.OIDCController do
  use PandexWeb, :controller

  alias Pandex.OIDC
  alias Pandex.Security

  def configuration(conn, _params) do
    json(conn, OIDC.discovery_metadata())
  end

  def jwks(conn, _params) do
    with {:ok, keys} <- Security.get_public_keys() do
      json(conn, %{keys: Enum.map(keys, &public_jwk/1)})
    end
  end

  defp public_jwk(%{public_key: public_key, kid: kid, algorithm: algorithm}) do
    public_key
    |> Map.put("kid", kid)
    |> Map.put("alg", algorithm)
    |> Map.put_new("use", "sig")
  end
end
