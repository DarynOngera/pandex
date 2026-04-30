defmodule PandexWeb.PageController do
  use PandexWeb, :controller

  def home(conn, _params) do
    render(conn, :home)
  end
end
