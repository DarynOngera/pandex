defmodule Pandex.Security.KeyCache do
  @moduledoc """
  ETS-backed read cache for signing keys and JWKS.

  Owned by a supervised GenServer so the ETS table survives process crashes.
  All cache misses fall through to PostgreSQL — there is no stale-read risk.
  """
  use GenServer

  @table :pandex_key_cache

  # ── Client API ────────────────────────────────────────────────────────────────

  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  def get_active do
    case :ets.lookup(@table, :active_key) do
      [{:active_key, key}] -> {:ok, key}
      [] -> :miss
    end
  end

  def get_jwks do
    case :ets.lookup(@table, :jwks) do
      [{:jwks, keys}] -> {:ok, keys}
      [] -> :miss
    end
  end

  def put_active(key), do: GenServer.cast(__MODULE__, {:put, :active_key, key})
  def put_jwks(keys), do: GenServer.cast(__MODULE__, {:put, :jwks, keys})
  def invalidate, do: GenServer.cast(__MODULE__, :invalidate)

  # ── Server ────────────────────────────────────────────────────────────────────

  @impl true
  def init(_opts) do
    :ets.new(@table, [:named_table, :public, read_concurrency: true])
    {:ok, %{}}
  end

  @impl true
  def handle_cast({:put, key, value}, state) do
    :ets.insert(@table, {key, value})
    {:noreply, state}
  end

  def handle_cast(:invalidate, state) do
    :ets.delete_all_objects(@table)
    {:noreply, state}
  end
end
