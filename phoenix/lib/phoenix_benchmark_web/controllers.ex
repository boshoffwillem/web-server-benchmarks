defmodule PhoenixBenchmarkWeb.AuthController do
  import Plug.Conn
  require Logger

  alias PhoenixBenchmark.Repositories.UserRepository
  alias PhoenixBenchmark.Auth

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

defmodule PhoenixBenchmarkWeb.UserController do
  import Plug.Conn
  alias PhoenixBenchmark.Repositories.UserRepository

  def get_user(conn, %{"id" => id}) do
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

defmodule PhoenixBenchmarkWeb.ProductController do
  import Plug.Conn
  alias PhoenixBenchmark.Repositories.ProductRepository

  def get_all_products(conn, _params) do
    products = ProductRepository.get_all_products()
    send_json(conn, 200, %{"products" => products})
  end

  def get_product(conn, %{"id" => id}) do
    case ProductRepository.get_product_by_id(id) do
      nil ->
        send_json(conn, 404, %{"error" => "Product not found"})

      product ->
        send_json(conn, 200, %{"product" => product})
    end
  end

  defp send_json(conn, status, data) do
    conn
    |> put_status(status)
    |> put_resp_header("content-type", "application/json")
    |> send_resp(status, Jason.encode!(data))
  end
end

defmodule PhoenixBenchmarkWeb.CategoryController do
  import Plug.Conn
  alias PhoenixBenchmark.Repositories.CategoryRepository

  def get_category(conn, %{"id" => id}) do
    case CategoryRepository.get_category_by_id(id) do
      nil ->
        send_json(conn, 404, %{"error" => "Category not found"})

      category ->
        send_json(conn, 200, %{"category" => category})
    end
  end

  defp send_json(conn, status, data) do
    conn
    |> put_status(status)
    |> put_resp_header("content-type", "application/json")
    |> send_resp(status, Jason.encode!(data))
  end
end
