defmodule Pandex.Mailer do
  @moduledoc """
  Pandex mail delivery module.

  Backed by Swoosh. Adapter is configured per-environment:
    - dev/test: Swoosh.Adapters.Local (no external delivery)
    - production: configure a real adapter in config/runtime.exs
      e.g. Swoosh.Adapters.Mailgun, Swoosh.Adapters.SMTP, etc.
  """
  use Swoosh.Mailer, otp_app: :pandex
end
