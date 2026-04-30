defmodule Pandex.Audit do
  @moduledoc """
  Audit context — append-only event log.

  Rules:
    - This context exposes NO update or delete functions.
    - `log/3` is intentionally synchronous so events cannot be silently dropped.
    - Callers should wrap `log/3` + their mutation in the same `Ecto.Multi`
      to guarantee atomicity.

  Standard event types:
    login_success, login_failed, logout,
    token_issued, token_revoked, token_rotated, token_reuse_detected,
    client_created, client_updated,
    user_created, user_suspended,
    signing_key_rotated,
    admin_action
  """
  import Ecto.Query
  alias Pandex.Repo
  alias Pandex.Audit.AuditEvent

  @doc """
  Record an audit event.

  ## Parameters
    - `tenant_id`  — The tenant scope for this event (required).
    - `event_type` — String event type, e.g. `\"login_success\"`.
    - `attrs`      — Map with optional: `actor_id`, `target_id`, `target_type`, `metadata`.
  """
  def log(tenant_id, event_type, attrs \\ %{}) do
    %AuditEvent{}
    |> AuditEvent.changeset(
      Map.merge(attrs, %{
        tenant_id: tenant_id,
        event_type: event_type
      })
    )
    |> Repo.insert()
  end

  @doc "Return paginated audit events for a tenant, newest first."
  def list_events(tenant_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 50)
    offset = Keyword.get(opts, :offset, 0)

    AuditEvent
    |> where([e], e.tenant_id == ^tenant_id)
    |> order_by([e], desc: e.inserted_at)
    |> limit(^limit)
    |> offset(^offset)
    |> Repo.all()
  end

  @doc "Filter events by actor."
  def list_events_by_actor(tenant_id, actor_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 50)

    AuditEvent
    |> where([e], e.tenant_id == ^tenant_id and e.actor_id == ^actor_id)
    |> order_by([e], desc: e.inserted_at)
    |> limit(^limit)
    |> Repo.all()
  end

  @doc "Filter events by type."
  def list_events_by_type(tenant_id, event_type, opts \\ []) do
    limit = Keyword.get(opts, :limit, 50)

    AuditEvent
    |> where([e], e.tenant_id == ^tenant_id and e.event_type == ^event_type)
    |> order_by([e], desc: e.inserted_at)
    |> limit(^limit)
    |> Repo.all()
  end
end
