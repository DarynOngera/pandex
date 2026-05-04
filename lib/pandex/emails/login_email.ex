defmodule Pandex.Emails.LoginEmail do
  @moduledoc """
  Composes login-related emails.
 
  Supports:
    - Magic link emails (clickable link carrying the raw code)
    - OTP emails (6-digit code for manual entry)
 
  In production, set OIDC_ISSUER so links point at the real domain.
  In dev, set `config :pandex, :expose_login_challenge_codes, true` and
  the raw code is also returned in the API response for local testing
  without actually sending email.
  """
  import Swoosh.Email
 
  @from_name "Pandex Auth"
 
  @doc """
  Build a magic-link email.
 
  The `raw_code` is embedded in a login URL. The recipient clicks the link
  and the application POSTs the code to `/login/challenges/consume`.
 
  ## Parameters
    - `to_email`  — recipient address
    - `tenant_id` — used to scope the consume request
    - `raw_code`  — the plaintext challenge code (never stored)
  """
  def magic_link(to_email, tenant_id, raw_code) do
    login_url = build_magic_link_url(tenant_id, raw_code)
    from_address = from_address()
 
    new()
    |> to(to_email)
    |> from({@from_name, from_address})
    |> subject("Your sign-in link")
    |> html_body(magic_link_html(login_url))
    |> text_body(magic_link_text(login_url))
  end
 
  @doc """
  Build an OTP email.
 
  The `raw_code` is displayed directly for the user to type. In practice
  you may want to format it as a shorter numeric code — that's a Sessions
  context concern (code generation), not the mailer's.
 
  ## Parameters
    - `to_email`  — recipient address
    - `raw_code`  — the plaintext challenge code (never stored)
  """
  def otp(to_email, raw_code) do
    from_address = from_address()
 
    new()
    |> to(to_email)
    |> from({@from_name, from_address})
    |> subject("Your sign-in code")
    |> html_body(otp_html(raw_code))
    |> text_body(otp_text(raw_code))
  end
 
  # ── Private ───────────────────────────────────────────────────────────────────
 
  defp from_address do
    Application.get_env(:pandex, :mailer_from, "noreply@pandex.local")
  end
 
  defp build_magic_link_url(tenant_id, raw_code) do
    issuer = Application.fetch_env!(:pandex, :oidc_issuer)
    "#{issuer}/login/magic?tenant_id=#{URI.encode_www_form(tenant_id)}&code=#{URI.encode_www_form(raw_code)}"
  end
 
  defp magic_link_html(login_url) do
    """
    <!DOCTYPE html>
    <html>
      <body style="font-family: sans-serif; max-width: 480px; margin: 40px auto; color: #111;">
        <h2>Sign in to your account</h2>
        <p>Click the link below to sign in. This link expires in 15 minutes and can only be used once.</p>
        <p style="margin: 24px 0;">
          <a href="#{login_url}"
             style="background:#4f46e5;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:bold;">
            Sign in
          </a>
        </p>
        <p style="color:#666;font-size:13px;">
          If you didn't request this, you can safely ignore this email.
        </p>
        <hr style="border:none;border-top:1px solid #eee;margin:24px 0;" />
        <p style="color:#999;font-size:12px;">Or copy this link into your browser:</p>
        <p style="color:#999;font-size:12px;word-break:break-all;">#{login_url}</p>
      </body>
    </html>
    """
  end
 
  defp magic_link_text(login_url) do
    """
    Sign in to your account
 
    Click the link below to sign in. This link expires in 15 minutes and can only be used once.
 
    #{login_url}
 
    If you didn't request this, you can safely ignore this email.
    """
  end
 
  defp otp_html(raw_code) do
    """
    <!DOCTYPE html>
    <html>
      <body style="font-family: sans-serif; max-width: 480px; margin: 40px auto; color: #111;">
        <h2>Your sign-in code</h2>
        <p>Enter the code below to sign in. This code expires in 15 minutes and can only be used once.</p>
        <p style="margin: 24px 0; font-size: 32px; font-weight: bold; letter-spacing: 4px; font-family: monospace;">
          #{raw_code}
        </p>
        <p style="color:#666;font-size:13px;">
          If you didn't request this, you can safely ignore this email.
        </p>
      </body>
    </html>
    """
  end
 
  defp otp_text(raw_code) do
    """
    Your sign-in code
 
    #{raw_code}
 
    This code expires in 15 minutes and can only be used once.
    If you didn't request this, you can safely ignore this email.
    """
  end
end
