defmodule AshWeb.UserController do
  use AshWeb, :controller
  alias Ash.Repositories.UserRepository

  def index(conn, _params) do
    case UserRepository.get_all_users() do
      nil ->
        send_json(conn, 404, %{"error" => "Users not found"})

      users ->
        send_json(conn, 200, %{"users" => users})
    end
  end

  def show(conn, %{"id" => id}) do
    case UserRepository.get_user_by_id(id) do
      nil ->
        send_json(conn, 404, %{"error" => "User not found"})

      user ->
        send_json(conn, 200, %{"user" => user})
    end
  end

  defp send_json(conn, status, data) do
    conn
    |> put_status(status)
    |> put_resp_header("content-type", "application/json")
    |> send_resp(status, Jason.encode!(data))
  end
end
