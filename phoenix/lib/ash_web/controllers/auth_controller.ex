defmodule AshWeb.AuthController do
  use AshWeb, :controller
  require Logger

  alias Ash.Repositories.UserRepository
  alias Ash.Auth

  def login(conn, params) do
    email = Map.get(params, "email") || Map.get(params, :email)
    password = Map.get(params, "password") || Map.get(params, :password)

    case UserRepository.get_user_by_email(email) do
      nil ->
        send_error(conn, 401, "Unauthorized")

      user ->
        if user.password == password do
          token = Auth.generate_token(user)
          send_json(conn, 200, %{"token" => token})
        else
          send_error(conn, 401, "Unauthorized")
        end
    end
  end

  defp send_json(conn, status, data) do
    conn
    |> put_status(status)
    |> put_resp_header("content-type", "application/json")
    |> send_resp(status, Jason.encode!(data))
  end

  defp send_error(conn, status, message) do
    send_json(conn, status, %{"error" => message})
  end
end
