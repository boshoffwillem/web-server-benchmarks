defmodule AshWeb.PageController do
  use AshWeb, :controller

  def home(conn, _params) do
    render(conn, :home)
  end
end
