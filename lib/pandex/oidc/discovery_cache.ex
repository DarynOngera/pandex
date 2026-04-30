defmodule Pandex.OIDC.DiscoveryCache do
  @moduledoc "ETS cache for OIDC discovery metadata. TTL enforced by timestamp."
  use GenServer

  @table :pandex_discovery_cache
  # 5-minute TTL for discovery document
  @ttl_seconds 300

  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  def get do
    case :ets.lookup(@table, :meta) do
      [{:meta, {meta, inserted_at}}] ->
        if System.system_time(:second) - inserted_at < @ttl_seconds,
          do: {:ok, meta},
          else: :miss

      [] ->
        :miss
    end
  end

  def put(meta), do: GenServer.cast(__MODULE__, {:put, meta})

  @impl true
  def init(_),
    do:
      (
        :ets.new(@table, [:named_table, :public, read_concurrency: true])
        {:ok, %{}}
      )

  @impl true
  def handle_cast({:put, meta}, state) do
    :ets.insert(@table, {:meta, {meta, System.system_time(:second)}})
    {:noreply, state}
  end
end
