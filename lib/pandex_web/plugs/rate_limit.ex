defmodule PandexWeb.Plugs.RateLimit do
  @moduledoc """
  Plug that enforces per-IP (or per-key) rate limits using Hammer.

  Usage in a controller or router pipeline:

      plug PandexWeb.Plugs.RateLimit,
        bucket: "login",
        limit: 10,
        window_ms: 60_000

  Options:
    - `:bucket`    — string bucket name, used as part of the Hammer key.
    - `:limit`     — maximum number of requests allowed in `:window_ms`.
    - `:window_ms` — sliding window in milliseconds (default: 60_000).
    - `:key_fn`    — 1-arity function `conn -> string` for the rate-limit key.
                     Defaults to remote IP. Override for per-user or per-client
                     limits once the request is authenticated.

  On limit breach:
    - Returns HTTP 429 with a JSON error body.
    - Sets `Retry-After` header (seconds until window resets).
    - Halts the connection — no downstream plugs run.

  On success:
    - Sets `X-RateLimit-Limit` and `X-RateLimit-Remaining` response headers.
  """
  import Plug.Conn
  import Phoenix.Controller, only: [json: 2]

  require Logger

  @default_window_ms 60_000

  def init(opts) do
    %{
      bucket: Keyword.fetch!(opts, :bucket),
      limit: Keyword.fetch!(opts, :limit),
      window_ms: Keyword.get(opts, :window_ms, @default_window_ms),
      key_fn: Keyword.get(opts, :key_fn, &default_key/1)
    }
  end

  def call(conn, %{bucket: bucket, limit: limit, window_ms: window_ms, key_fn: key_fn}) do
    key = "#{bucket}:#{key_fn.(conn)}"

    case Hammer.check_rate(key, window_ms, limit) do
      {:allow, count} ->
        conn
        |> put_resp_header("x-ratelimit-limit", to_string(limit))
        |> put_resp_header("x-ratelimit-remaining", to_string(max(limit - count, 0)))

      {:deny, _limit} ->
        retry_after = div(window_ms, 1_000)

        Logger.warning("Rate limit exceeded: bucket=#{bucket} key=#{key}")

        conn
        |> put_resp_header("retry-after", to_string(retry_after))
        |> put_status(:too_many_requests)
        |> json(%{
          error: "rate_limit_exceeded",
          error_description: "Too many requests. Please try again later.",
          retry_after: retry_after
        })
        |> halt()
    end
  end

  # Default key: remote IP address.
  # Falls back to "unknown" if the IP cannot be determined (e.g. behind a proxy
  # without proper X-Forwarded-For configuration).
  defp default_key(conn) do
    case conn.remote_ip do
      {a, b, c, d} -> "#{a}.#{b}.#{c}.#{d}"
      {a, b, c, d, e, f, g, h} -> "#{a}:#{b}:#{c}:#{d}:#{e}:#{f}:#{g}:#{h}"
      _ -> "unknown"
    end
  end
end
