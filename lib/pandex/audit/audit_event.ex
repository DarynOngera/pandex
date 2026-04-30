defmodule Pandex.Audit.AuditEvent do
  @moduledoc "Append-only audit event record."
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "audit_events" do
    field :tenant_id, :binary_id
    # user_id who performed the action
    field :actor_id, :binary_id
    # resource affected (e.g. client_id, user_id)
    field :target_id, :binary_id
    # "client" | "user" | "token" etc.
    field :target_type, :string
    field :event_type, :string
    field :metadata, :map, default: %{}

    # Intentionally NO updated_at — records are immutable.
    timestamps(type: :utc_datetime, updated_at: false)
  end

  def changeset(event, attrs) do
    event
    |> cast(attrs, [:tenant_id, :actor_id, :target_id, :target_type, :event_type, :metadata])
    |> validate_required([:tenant_id, :event_type])
  end
end
